"""Abruptly terminate one independently authorized Linux process through a pidfd."""
import hashlib
import math
import os
from pathlib import Path
import re
import select
import signal
import sys
import time


_FIELDS = {'pid', 'start_ticks', 'uid', 'gid', 'exe_device', 'exe_inode',
           'pid_namespace_device', 'pid_namespace_inode',
           'mount_namespace_device', 'mount_namespace_inode', 'cgroup_sha256'}


def process_identity(pid):
    """Private observation only; caller must independently authorize its scope."""
    if not sys.platform.startswith('linux') or type(pid) is not int or pid <= 1:
        raise ValueError('Linux process identity unavailable')
    root = Path('/proc') / str(pid)
    def read(name):
        with (root / name).open('rb') as stream:
            value = stream.read(65537)
        if len(value) > 65536: raise ValueError('Process observation exceeds limit')
        return value
    def started():
        data = read('stat')
        end = data.rfind(b')')
        if end < 0 or data[:data.find(b' ')] != str(pid).encode():
            raise ValueError('Process identity unavailable')
        fields = data[end+2:].split()
        if fields[0] in (b'Z', b'X', b'x'): raise ValueError('Process already exited')
        return int(fields[19])
    start = started()
    credentials = {}
    for line in read('status').splitlines():
        for label, key in ((b'Uid:', 'uid'), (b'Gid:', 'gid')):
            if line.startswith(label):
                values = line.split()[1:]
                if len(values) != 4: raise ValueError('Process credentials unavailable')
                credentials[key] = int(values[1])
    executable = (root / 'exe').stat()
    value = dict(pid=pid, start_ticks=start, **credentials,
                 exe_device=executable.st_dev, exe_inode=executable.st_ino,
                 cgroup_sha256=hashlib.sha256(read('cgroup')).hexdigest())
    for namespace in ('pid', 'mnt'):
        identity = (root / 'ns' / namespace).stat()
        prefix = 'pid_namespace' if namespace == 'pid' else 'mount_namespace'
        value[prefix+'_device'], value[prefix+'_inode'] = identity.st_dev, identity.st_ino
    if started() != start or set(value) != _FIELDS:
        raise ValueError('Process identity changed')
    return value


def terminate_process(binding, *, check, monotonic_deadline, wall_deadline, timeout=5):
    """Require original node/runtime/owner authority from an independent callback.

    check(reserve) must bound its work, return exactly True, and verify the
    original sandbox, runtime, mapped container and controlling process. The
    binding is a prior private observation, never a grader-provided PID or a
    same-UID authorization. Caller owns restoration and the outer watchdog.
    This proves exit of the selected process, not absence of replacement workers
    or lease reclamation. No numeric-PID signal fallback is permitted.
    """
    if (not sys.platform.startswith('linux') or not hasattr(os, 'pidfd_open')
            or not hasattr(signal, 'pidfd_send_signal') or not callable(check)
            or not isinstance(binding, dict) or set(binding) != _FIELDS
            or any(type(binding[k]) is not int or binding[k] < 0 for k in _FIELDS-{'cgroup_sha256'})
            or binding['pid'] <= 1 or binding['pid'] == os.getpid()
            or any(binding[k] == 0 for k in ('start_ticks', 'exe_inode', 'pid_namespace_inode', 'mount_namespace_inode'))
            or not isinstance(binding['cgroup_sha256'], str)
            or not re.fullmatch('[0-9a-f]{64}', binding['cgroup_sha256'])
            or type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 10
            or any(type(v) not in (int, float) or not math.isfinite(v)
                   for v in (monotonic_deadline, wall_deadline))):
        raise ValueError('Process termination binding unavailable')
    binding = dict(binding)
    owner = os.getpid()
    monotonic_end = min(monotonic_deadline, time.monotonic()+timeout)
    wall_end = min(wall_deadline, time.time()+timeout)
    def remaining():
        value = min(monotonic_end-time.monotonic(), wall_end-time.time())
        if os.getpid() != owner or value <= 0:
            raise ValueError('Process termination lifetime unavailable')
        return value
    def authorized():
        if check(remaining()) is not True:
            raise ValueError('Process termination authority unavailable')
        remaining()
    descriptor = None
    try:
        authorized()
        descriptor = os.pidfd_open(binding['pid'], 0)
        if process_identity(binding['pid']) != binding:
            raise ValueError()
        authorized()
        if process_identity(binding['pid']) != binding or select.select([descriptor], [], [], 0)[0]:
            raise ValueError()
        remaining()
        signal.pidfd_send_signal(descriptor, signal.SIGKILL, None, 0)
        while not select.select([descriptor], [], [], min(.05, remaining()))[0]:
            authorized()
        authorized()
        return {'outcome': 'process_terminated', 'process_exit_verified': True,
                'signal': 'SIGKILL', 'pidfd_used': True}
    except Exception:
        raise ValueError('Process termination unavailable') from None
    finally:
        if descriptor is not None: os.close(descriptor)
