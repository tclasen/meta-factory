"""Private node-event FD admission; never a full-history coverage attestation."""
import array
import copy
import os
import re
import socket
import stat
import struct
import sys
import threading
import time
import uuid

from .cri_staging import PrivateCRIStaging, provisional_entry, _key
from .evidence import positive
from .log_retention import MAX_FILES, _file_identity


HEADER = struct.Struct('!4sQQQI')
ACK = struct.Struct('!4sQ')
MAX_PATH = 1024
MAX_EVENTS = 4096
_PEER_FIELDS = {'pid', 'uid', 'gid', 'start_ticks', 'mount_device', 'mount_inode'}


def linux_peer_identity(pid):
    """Private /proc projection; caller must independently bind its original node.

    This observes a process, not its authorization. Its start ticks and held
    mount namespace identity must match independently captured trusted values.
    Raw process names, command lines, environments and runtime config are unused.
    """
    if type(pid) is not int or pid <= 0:
        raise ValueError('Private event peer required')
    try:
        with open('/proc/'+str(pid)+'/stat', 'rb') as stream:
            value = stream.read(4097)
        if len(value) > 4096:
            raise ValueError()
        # comm may contain spaces and parentheses; fields after its last ')' are
        # kernel-controlled. starttime is field22, offset19 after the comm.
        suffix = value[value.rindex(b')')+2:].split()
        start = int(suffix[19])
        if suffix[0] in (b'Z', b'X', b'x') or start < 0:
            raise ValueError()
        namespace = os.stat('/proc/'+str(pid)+'/ns/mnt')
        return dict(pid=pid, start_ticks=start, mount_device=namespace.st_dev,
                    mount_inode=namespace.st_ino)
    except (OSError, ValueError, IndexError):
        raise ValueError('Private event peer unavailable') from None


def _peer(value):
    if (not isinstance(value, dict) or set(value) != _PEER_FIELDS
            or any(type(item) is not int or item < 0 for item in value.values())
            or value['pid'] == 0 or value['mount_inode'] == 0):
        raise ValueError('Original private event peer required')
    return copy.deepcopy(value)


def _entry(path, namespace):
    parts = path.split('/')
    if len(parts) != 7 or parts[:4] != ['', 'var', 'log', 'pods']:
        raise ValueError('Private event path unavailable')
    pod = parts[4].split('_')
    if len(pod) != 3 or pod[0] != namespace or str(uuid.UUID(pod[2])) != pod[2]:
        raise ValueError('Private event namespace unavailable')
    match = re.fullmatch(r'(0|[1-9][0-9]{0,6})\.log', parts[6])
    if match is None:
        raise ValueError('Private event generation unavailable')
    return provisional_entry(dict(namespace=pod[0], pod_name=pod[1], pod_uid=pod[2],
                                   container_name=parts[5], restart_index=int(match[1])))


class PrivateCRIEventReceiver:
    """Admit bounded ordered packets from an independently authenticated helper.

    Trusted caller owns a private AF_UNIX SEQPACKET connection outside the node
    log mount and supplies original SO_PEERCRED/start ticks/mount identity plus
    Node UID. check(reserve) verifies original node/runtime/Namespace UID, owner
    and both clocks. event_check(proof,reserve) independently verifies canonical
    path, provisional declaration, node and observed device/inode. Helper is a
    trusted operator component; socket peer authentication alone does not prove
    event origin or that its event stream is complete.

    CRF1 packets: network-order sequence/device/inode/path-size followed by ASCII
    absolute canonical /var/log/pods path and exactly one SCM_RIGHTS read-only
    regular FD. CRA1 ACK is sent only after guarded staging succeeds. Transferred file FDs are closed after staging duplicates them. Ownership of
    the connection transfers to this receiver after static input validation; the
    caller must keep no aliases and must not use it thereafter. Duplicate opens of the same entry/
    inode are acknowledged without inventing another generation. Any reused
    inode, replacement generation, malformed/overflow/lost packet, peer loss,
    EOF, guard/limit or staging failure closes this receiver and staging together.
    Prior bound positives survive; unbound data is discarded. Native helper must
    report queue overflow by closing/refusing its stream, never silently resume.

    No bytes/path/peer IDs appear in public receipts. poll is nonblocking; use an
    owned bounded child for /proc/filesystem/guard callbacks. This does not prove
    bootstrap, runtime births, writer closure, API/time fences or owner-death
    containment. Every receipt explicitly retains history_complete=False.
    """
    def __init__(self, staging, connection, *, peer, node_uid, check, event_check, deadline):
        positive(deadline, 'Private event deadline')
        if (not sys.platform.startswith('linux') or type(staging) is not PrivateCRIStaging
                or not isinstance(connection, socket.socket) or connection.family != socket.AF_UNIX
                or not callable(check) or not callable(event_check) or deadline > staging._deadline):
            raise ValueError('Private event receiver inputs required')
        staging._owned()
        _file_identity(dict(node_uid=node_uid, device=0, inode=1))
        self._staging, self._peer, self._node = staging, _peer(peer), node_uid
        self._check, self._event_check, self._deadline = check, event_check, deadline
        self._owner, self._lock = os.getpid(), threading.RLock()
        self._connection, self._seen, self._used = None, {}, set()
        self._events = self._duplicates = self._polls = 0
        self._valid, self._closed, self._cleanup_ok = True, False, True
        try:
            self._connection = connection
            if connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET:
                raise ValueError('Private event socket type unavailable')
            self._verify()
        except BaseException as error:
            self._cleanup()
            if not isinstance(error, Exception): raise
            raise ValueError('Private event receiver unavailable') from None

    def _owned(self):
        if os.getpid() != self._owner:
            raise ValueError('Private event receiver owner unavailable')

    def _verify(self):
        if (not self._valid or self._closed or time.monotonic()+5 >= self._deadline
                or self._check(5) is not True or not self._staging.summary()['valid']):
            raise ValueError('Private event lifetime unavailable')
        credentials = self._connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        pid, uid, gid = struct.unpack('3i', credentials)
        if (dict(uid=uid, gid=gid, **linux_peer_identity(pid)) != self._peer
                or self._check(5) is not True):
            raise ValueError('Private event peer unavailable')

    def _cleanup(self):
        self._valid, self._closed = False, True
        if self._connection is not None:
            try: self._connection.close()
            except OSError: self._cleanup_ok = False
            self._connection = None
        try: self._cleanup_ok &= self._staging.close()['descriptors_closed']
        except Exception: self._cleanup_ok = False

    def _admit(self, data, ancillary, flags):
        descriptors = []
        try:
            unexpected = False
            for level, kind, raw in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    values = array.array('i')
                    if len(raw) % values.itemsize:
                        unexpected = True
                        raw = raw[:len(raw)-len(raw)%values.itemsize]
                    values.frombytes(raw); descriptors.extend(values)
                else: unexpected = True
            if (unexpected or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                    or len(descriptors) != 1 or len(data) < HEADER.size):
                raise ValueError('Private event framing unavailable')
            magic, sequence, device, inode, size = HEADER.unpack_from(data)
            if (magic != b'CRF1' or sequence != self._events+1 or not 1 <= size <= MAX_PATH
                    or len(data) != HEADER.size+size or self._events >= MAX_EVENTS):
                raise ValueError('Private event sequence unavailable')
            path = data[HEADER.size:].decode('ascii')
            entry = _entry(path, self._staging._retention._binding['name'])
            descriptor = descriptors[0]
            observed = os.fstat(descriptor)
            if (not stat.S_ISREG(observed.st_mode) or os.get_inheritable(descriptor)
                    or (observed.st_dev, observed.st_ino) != (device, inode)):
                raise ValueError('Private event file unavailable')
            import fcntl
            mode = fcntl.fcntl(descriptor, fcntl.F_GETFL)
            if mode & os.O_ACCMODE != os.O_RDONLY or mode & getattr(os, 'O_PATH', 0):
                raise ValueError('Private event file mode unavailable')
            identity = dict(node_uid=self._node, device=device, inode=inode)
            proof = dict(entry=entry, path=path, identity=identity)
            self._verify()
            if self._event_check(copy.deepcopy(proof), 5) is not True:
                raise ValueError('Private event binding unavailable')
            self._verify()
            key, file_key = _key(entry), _file_identity(identity)
            if key in self._seen:
                if self._seen[key] != file_key:
                    raise ValueError('Private event generation replaced')
                self._duplicates += 1
            else:
                if file_key in self._used or len(self._used) >= MAX_FILES:
                    raise ValueError('Private event inode reused')
                self._staging.stage_descriptor(entry, descriptor, node_uid=self._node,
                    check=lambda value, reserve: self._check(reserve))
                self._seen[key] = file_key; self._used.add(file_key)
            if self._event_check(copy.deepcopy(proof), 5) is not True:
                raise ValueError('Private event binding changed')
            self._verify()
            ack = ACK.pack(b'CRA1', sequence)
            if self._connection.send(ack, socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL) != len(ack):
                raise ValueError('Private event acknowledgement unavailable')
            self._events += 1
        finally:
            for descriptor in descriptors: os.close(descriptor)

    def poll(self):
        self._owned()
        with self._lock:
            try:
                self._verify()
                if self._polls >= MAX_EVENTS:
                    raise ValueError('Private event poll bound')
                self._polls += 1
                # One packet per poll bounds admission and guard work. Kernel
                # closes undisclosed FDs on ancillary truncation; every delivered
                # FD is closed in _admit, even when framing/identity is refused.
                try:
                    data, ancillary, flags, _ = self._connection.recvmsg(
                        HEADER.size+MAX_PATH, socket.CMSG_SPACE(64*array.array('i').itemsize),
                        socket.MSG_DONTWAIT | socket.MSG_CMSG_CLOEXEC)
                except BlockingIOError:
                    return self.summary()
                self._admit(data, ancillary, flags)
                self._verify()
                return self.summary()
            except BaseException as error:
                self._cleanup()
                if not isinstance(error, Exception): raise
                raise ValueError('Private CRI event admission unavailable') from None

    def summary(self):
        self._owned()
        with self._lock:
            return dict(outcome='private_cri_event_receiver', events=self._events,
                        sources=len(self._seen), duplicate_opens=self._duplicates, polls=self._polls,
                        valid=self._valid and not self._closed,
                        descriptors_closed=self._closed and self._cleanup_ok, history_complete=False)

    def close(self):
        self._owned()
        with self._lock:
            self._cleanup()
            return self.summary()
