"""Operator-owned kernel proc view retained across mount/root changes."""
import ctypes
import fcntl
import os
import stat
import sys


class _StatFS(ctypes.Structure):
    # Linux asm-generic/statfs.h, the 64-bit aarch64/x86_64 ABI only.
    _fields_ = [(name, ctypes.c_long) for name in (
        'kind', 'block_size', 'blocks', 'free_blocks', 'available_blocks',
        'files', 'free_files')] + [('fsid', ctypes.c_int * 2)] + [
        (name, ctypes.c_long) for name in ('name_length', 'fragment_size', 'flags')
    ] + [('spare', ctypes.c_long * 4)]


class LinuxProcView:
    """Open genuine /proc in the operator's PID namespace before chroot/setns.

    The caller owns this view; guards borrow it and never close it. Procfs magic,
    directory identity, descriptor flags, self PID/start and PID namespace are
    checked on use. A fake proc directory or a view of another PID namespace
    cannot authorize socket peers. No paths, arbitrary proc files or descriptor
    aliases are accepted as inputs. Raw cgroups stay PRIVATE.

    Changing mount namespace/root is supported; changing process ownership or
    PID namespace is not. Peer authorization still requires independent original
    mappings and bounded callbacks. This supplies observations, not complete
    event, Namespace/API, filesystem or writer history.
    """
    def __init__(self):
        self._fd = None
        self._owner = os.getpid()
        try:
            if (not sys.platform.startswith('linux') or ctypes.sizeof(ctypes.c_long) != 8
                    or os.uname().machine not in ('aarch64', 'x86_64')):
                raise ValueError()
            self._statfs = ctypes.CDLL(None, use_errno=True).fstatfs
            self._statfs.argtypes = (ctypes.c_int, ctypes.POINTER(_StatFS))
            self._statfs.restype = ctypes.c_int
            self._fd = os.open('/proc', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            root = os.fstat(self._fd)
            self._root = (root.st_dev, root.st_ino)
            self._start = self._process(self._owner)['start_ticks']
            namespace = os.stat('self/ns/pid', dir_fd=self._fd)
            self._namespace = (namespace.st_dev, namespace.st_ino)
            self._validate()
        except Exception:
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None
            raise ValueError('Private kernel process view unavailable') from None

    def _owned(self):
        if os.getpid() != self._owner:
            raise ValueError('Private kernel process view owner unavailable')

    def _read(self, pid, name):
        if type(pid) is not int or pid <= 0:
            raise ValueError()
        descriptor = os.open(str(pid)+'/'+name, os.O_RDONLY | os.O_CLOEXEC,
                             dir_fd=self._fd)
        try:
            value = os.read(descriptor, 4097)
            if not 0 < len(value) <= 4096:
                raise ValueError()
            return value
        finally:
            os.close(descriptor)

    def _process(self, pid):
        raw = self._read(pid, 'stat')
        if int(raw[:raw.index(b'(')].strip()) != pid:
            raise ValueError()
        suffix = raw[raw.rindex(b')')+2:].split()
        start = int(suffix[19])
        if suffix[0] in (b'Z', b'X', b'x') or start < 0:
            raise ValueError()
        namespace = os.stat(str(pid)+'/ns/mnt', dir_fd=self._fd)
        return dict(pid=pid, start_ticks=start, mount_device=namespace.st_dev,
                    mount_inode=namespace.st_ino)

    def _validate(self):
        self._owned()
        if self._fd is None:
            raise ValueError()
        root = os.fstat(self._fd)
        filesystem = _StatFS()
        if (not stat.S_ISDIR(root.st_mode) or (root.st_dev, root.st_ino) != self._root
                or fcntl.fcntl(self._fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
                or not fcntl.fcntl(self._fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
                or self._statfs(self._fd, ctypes.byref(filesystem)) != 0
                or filesystem.kind != 0x9fa0
                or os.readlink('self', dir_fd=self._fd) != str(self._owner)
                or self._process(self._owner)['start_ticks'] != self._start):
            raise ValueError()
        namespace = os.stat('self/ns/pid', dir_fd=self._fd)
        if (namespace.st_dev, namespace.st_ino) != self._namespace:
            raise ValueError()

    def identity(self, pid):
        try:
            self._validate()
            value = self._process(pid)
            self._validate()
            if self._process(pid) != value:
                raise ValueError()
            return value
        except Exception:
            raise ValueError('Private kernel process identity unavailable') from None

    def executable(self, pid):
        try:
            before = self.identity(pid)
            value = os.stat(str(pid)+'/exe', dir_fd=self._fd)
            if self.identity(pid) != before:
                raise ValueError()
            return value
        except Exception:
            raise ValueError('Private kernel executable unavailable') from None

    def cgroup(self, pid):
        """Return private complete cgroup bytes, with process/view checks."""
        try:
            before = self.identity(pid)
            value = self._read(pid, 'cgroup')
            if self.identity(pid) != before:
                raise ValueError()
            return value
        except Exception:
            raise ValueError('Private kernel cgroup unavailable') from None

    def close(self):
        self._owned()
        if self._fd is not None:
            descriptor, self._fd = self._fd, None
            os.close(descriptor)
