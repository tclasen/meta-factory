"""Authenticate an independently mapped operator RPC client on its actual FD."""
import copy
import math
import os
import socket
import struct
import sys
import time

from .cri_events import linux_peer_identity
from .cri_relay import relay_private_rpc


_FIELDS = {'pid', 'uid', 'gid', 'start_ticks', 'mount_device', 'mount_inode',
           'exe_device', 'exe_inode'}


class PrivateCRIClientGuard:
    """Peer comes from independent operator-process observation, not admission.

    check(reserve) binds the process's full cgroup, owning supervisor and clocks
    independently. Never authorize a client from UID alone. Callbacks are bounded
    trusted code in an operator-owned guarded process.
    """
    def __init__(self, *, peer, check, deadline):
        if (not sys.platform.startswith('linux') or not isinstance(peer, dict)
                or set(peer) != _FIELDS or any(type(v) is not int or v < 0 for v in peer.values())
                or any(peer[k] == 0 for k in ('pid', 'start_ticks', 'mount_inode', 'exe_inode'))
                or not callable(check) or type(deadline) not in (int, float)
                or not math.isfinite(deadline)):
            raise ValueError('Private RPC client mapping unavailable')
        self._peer = copy.deepcopy(peer)
        self._check, self._deadline, self._owner = check, deadline, os.getpid()

    def __call__(self, connection, reserve):
        try:
            if (os.getpid() != self._owner or not isinstance(connection, socket.socket)
                    or connection.family != socket.AF_UNIX or connection.type != socket.SOCK_STREAM
                    or type(reserve) not in (int, float) or not math.isfinite(reserve) or reserve < 0
                    or time.monotonic()+reserve >= self._deadline or self._check(reserve) is not True):
                return False
            pid, uid, gid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            identity = linux_peer_identity(pid)
            executable = os.stat('/proc/'+str(pid)+'/exe')
            observed = dict(uid=uid, gid=gid, **identity,
                            exe_device=executable.st_dev, exe_inode=executable.st_ino)
            return (observed == self._peer and linux_peer_identity(pid) == identity
                    and time.monotonic()+reserve < self._deadline and self._check(reserve) is True)
        except Exception:
            return False


def serve_private_rpc_once(listener, runtime, *, client_guard, stop, deadline):
    """Own listener/runtime; accept one independently mapped client, then relay.

    Caller creates the listener in an exclusive operator-owned directory and
    supplies a runtime connection admitted against separate original observations.
    Authentication failure ends the attempt; no alternate client is tried. The
    caller owns pathname cleanup and a bounded process/watchdog. A listening
    socket is not evidence that the CRI subscription has been acknowledged.
    """
    client = None
    try:
        if (not isinstance(listener, socket.socket) or listener.family != socket.AF_UNIX
                or listener.type != socket.SOCK_STREAM
                or not isinstance(client_guard, PrivateCRIClientGuard)
                or type(deadline) not in (int, float) or not math.isfinite(deadline)):
            raise ValueError()
        listener.settimeout(None)
        listener.setblocking(False)
        while client is None:
            if time.monotonic()+5 >= deadline:
                raise ValueError()
            runtime.poll()
            try:
                client, _ = listener.accept()
            except (BlockingIOError, InterruptedError):
                time.sleep(.005)
        listener.close()
        if client_guard(client, 5) is not True:
            raise ValueError()
        return relay_private_rpc(client, runtime, check_client=client_guard,
                                 stop=stop, deadline=deadline)
    except Exception:
        raise ValueError('Private RPC client admission unavailable') from None
    finally:
        if client is not None:
            client.close()
        listener.close()
        runtime.close()
