"""Private bounded bytes on an independently admitted, held Linux runtime FD."""
import copy
import math
import os
import socket
import stat
import struct
import sys
import threading
import time

from .cri_events import linux_peer_identity


MAX_CHUNK_BYTES = 65536
MAX_TRAFFIC_BYTES = 64 * 1024 * 1024
_FIELDS = {'pid', 'uid', 'gid', 'start_ticks', 'mount_device', 'mount_inode',
           'exe_device', 'exe_inode', 'socket_device', 'socket_inode'}


class PrivateCRIRPCConnection:
    """Own a connected original-runtime socket and authenticate its actual FD.

    peer and endpoint must come from a separate trusted original-runtime
    observation. check(reserve) independently binds Node/Namespace, full cgroup,
    owner and clocks; it must not derive authorization from this connection.
    invalidate is bounded trusted cleanup for dependent decoders/collections.
    Callbacks and this instance run in a bounded operator-owned process.

    Each IO checks the actual SO_PEERCRED, process start/mount/executable, and
    original endpoint inode before and after IO. An unseen restored path swap
    cannot redirect this held FD; new connections require separate admission.
    Polling cannot prove absence of transient swaps or complete runtime history.
    Raw bytes are private; protocol framing, RPC semantics and intentional
    observation-window completion remain the caller's responsibility.
    """
    def __init__(self, connection, *, peer, endpoint, check, invalidate, deadline):
        self._connection = connection
        self._owner = os.getpid()
        self._lock = threading.RLock()
        self._valid = True
        self._invalidated = False
        self._received = self._sent = 0
        self._invalidate = invalidate
        try:
            if (not sys.platform.startswith('linux')
                    or not isinstance(connection, socket.socket)
                    or connection.family != socket.AF_UNIX
                    or connection.type != socket.SOCK_STREAM
                    or not isinstance(peer, dict) or set(peer) != _FIELDS
                    or any(type(v) is not int or v < 0 for v in peer.values())
                    or any(peer[k] == 0 for k in ('pid', 'mount_inode', 'exe_inode', 'socket_inode'))
                    or not isinstance(endpoint, str) or not endpoint.startswith('/')
                    or '\x00' in endpoint or len(os.fsencode(endpoint)) > 107
                    or not callable(check) or not callable(invalidate)
                    or type(deadline) not in (int, float) or not math.isfinite(deadline)):
                raise ValueError()
            self._peer = copy.deepcopy(peer)
            self._endpoint, self._check, self._deadline = endpoint, check, deadline
            # The caller transfers ownership, including any Python timeout mode.
            # All IO below uses MSG_DONTWAIT on this same authenticated socket.
            connection.settimeout(None)
            self._verify()
        except BaseException as error:
            self._discard()
            if not isinstance(error, Exception):
                raise
            raise ValueError('Private runtime connection unavailable') from None

    def _owned(self):
        if os.getpid() != self._owner:
            raise ValueError('Private runtime connection owner unavailable')

    def _identity(self):
        credentials = self._connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        pid, uid, gid = struct.unpack('3i', credentials)
        observed = dict(uid=uid, gid=gid, **linux_peer_identity(pid))
        executable = os.stat('/proc/'+str(pid)+'/exe')
        endpoint = os.lstat(self._endpoint)
        if not stat.S_ISSOCK(endpoint.st_mode):
            raise ValueError()
        observed.update(exe_device=executable.st_dev, exe_inode=executable.st_ino,
                        socket_device=endpoint.st_dev, socket_inode=endpoint.st_ino)
        if observed != self._peer or linux_peer_identity(pid) != {
                k: observed[k] for k in ('pid', 'start_ticks', 'mount_device', 'mount_inode')}:
            raise ValueError()

    def _verify(self):
        self._owned()
        if (not self._valid or time.monotonic()+5 >= self._deadline
                or self._check(5) is not True):
            raise ValueError()
        self._identity()
        if time.monotonic()+5 >= self._deadline:
            raise ValueError()

    def _discard(self):
        was_valid, self._valid = self._valid, False
        try:
            self._connection.close()
        except Exception:
            pass
        if was_valid and callable(self._invalidate):
            try:
                self._invalidate()
                self._invalidated = True
            except Exception:
                self._invalidated = False

    def _operation(self, action):
        with self._lock:
            self._owned()
            try:
                self._verify()
                result = action()
                self._verify()
                return result
            except BaseException as error:
                self._discard()
                if not isinstance(error, Exception):
                    raise
                raise ValueError('Private runtime transport unavailable') from None

    def poll(self):
        """Revalidate a held connection; never a complete-history receipt."""
        return self._operation(lambda: self.summary())

    def receive(self):
        """Return private bytes, or None when idle; unexpected EOF refuses."""
        def receive():
            remaining = MAX_TRAFFIC_BYTES-self._received-self._sent
            if remaining <= 0:
                raise ValueError()
            try:
                value = self._connection.recv(min(MAX_CHUNK_BYTES, remaining), socket.MSG_DONTWAIT)
            except (BlockingIOError, InterruptedError):
                return None
            if not value:
                raise ValueError()
            self._received += len(value)
            return value
        return self._operation(receive)

    def send(self, value):
        """Send a bounded private chunk; return consumed bytes (zero if busy)."""
        def send():
            if (type(value) is not bytes or not value or len(value) > MAX_CHUNK_BYTES
                    or self._received+self._sent+len(value) > MAX_TRAFFIC_BYTES):
                raise ValueError()
            try:
                size = self._connection.send(value, socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
            except (BlockingIOError, InterruptedError):
                return 0
            if size <= 0:
                raise ValueError()
            self._sent += size
            return size
        return self._operation(send)

    def summary(self):
        with self._lock:
            self._owned()
            return dict(outcome='private_cri_rpc_connection', valid=self._valid,
                        descriptors_closed=self._connection.fileno() < 0,
                        dependents_invalidated=self._invalidated,
                        received_bytes=self._received, sent_bytes=self._sent,
                        history_complete=False)

    def close(self):
        """Close the owned FD and invalidate dependent collection, idempotently."""
        with self._lock:
            self._owned()
            self._discard()
