"""Held kernel proc observations across actual root changes; no history claim."""
import os
from pathlib import Path
import socket
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from evaluation.cri_client import PrivateCRIClientGuard
from evaluation.cri_events import linux_peer_identity
from evaluation.cri_rpc import PrivateCRIRPCConnection
from evaluation.linux_proc import LinuxProcView


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux held proc view')
class LinuxProcTest(unittest.TestCase):
    def test_independent_observations_and_closed_view_refusal(self):
        view = LinuxProcView()
        self.addCleanup(view.close)
        pid = os.getpid()
        self.assertEqual(view.identity(pid), linux_peer_identity(pid))
        self.assertEqual(view.executable(pid), os.stat('/proc/self/exe'))
        self.assertEqual(view.cgroup(pid), Path('/proc/self/cgroup').read_bytes())
        view.close()
        for operation in (view.identity, view.executable, view.cgroup):
            with self.assertRaises(ValueError):
                operation(pid)

    def test_real_directory_cannot_impersonate_procfs(self):
        with tempfile.TemporaryDirectory() as directory:
            # Supply real live process files through links: rejection must be
            # due to the directory filesystem, not missing stat/ns content.
            pid = os.getpid()
            os.symlink('/proc/'+str(pid), Path(directory)/str(pid))
            os.symlink(str(pid), Path(directory)/'self')
            original = os.open
            def substituted(path, flags, **kwargs):
                return original(directory if path == '/proc' else path, flags, **kwargs)
            with patch('evaluation.linux_proc.os.open', side_effect=substituted):
                with self.assertRaises(ValueError):
                    LinuxProcView()

    def test_fork_cannot_borrow_parent_view(self):
        view = LinuxProcView()
        self.addCleanup(view.close)
        child = os.fork()
        if child == 0:
            try:
                view.identity(os.getpid())
            except ValueError:
                os._exit(0)
            os._exit(1)
        _, status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        self.assertEqual(view.identity(os.getpid()), linux_peer_identity(os.getpid()))

    @unittest.skipUnless(hasattr(os, 'chroot') and os.geteuid() == 0, 'Owned privileged Linux test')
    def test_actual_chroot_socket_guards_and_view_loss(self):
        # Independently observe before admission. Preserve root solely to restore
        # this owned test process; a production observer never exposes this FD.
        view = LinuxProcView()
        self.addCleanup(view.close)
        pid = os.getpid()
        executable = os.stat('/proc/self/exe')
        peer = dict(uid=os.getuid(), gid=os.getgid(), **linux_peer_identity(pid),
                    exe_device=executable.st_dev, exe_inode=executable.st_ino)
        cgroup = Path('/proc/self/cgroup').read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'runtime.sock'
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.addCleanup(listener.close)
            listener.bind(str(path)); listener.listen(2)
            clients, servers = [], []
            for _ in range(2):
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.addCleanup(client.close); client.connect(str(path)); clients.append(client)
                server, _ = listener.accept()
                self.addCleanup(server.close); servers.append(server)
            endpoint = path.stat()
            runtime_peer = dict(peer, socket_device=endpoint.st_dev, socket_inode=endpoint.st_ino)
            root = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            cwd = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            invalidations = []
            try:
                os.chroot(directory); os.chdir('/')
                self.assertFalse(os.path.exists('/proc'))
                self.assertEqual(view.identity(pid), {k: peer[k] for k in ('pid', 'start_ticks', 'mount_device', 'mount_inode')})
                self.assertEqual(view.cgroup(pid), cgroup)
                guard = PrivateCRIClientGuard(peer=peer, check=lambda reserve: True,
                    deadline=time.monotonic()+30, proc_view=view)
                self.assertTrue(guard(servers[0], 5))
                default = PrivateCRIClientGuard(peer=peer, check=lambda reserve: True,
                    deadline=time.monotonic()+30)
                self.assertFalse(default(servers[0], 5))
                wrong = PrivateCRIClientGuard(peer=dict(peer, pid=pid+1), check=lambda reserve: True,
                    deadline=time.monotonic()+30, proc_view=view)
                self.assertFalse(wrong(servers[0], 5))
                arguments = dict(peer=runtime_peer, endpoint='/runtime.sock', check=lambda reserve: True,
                    invalidate=lambda: invalidations.append(True), deadline=time.monotonic()+30)
                with self.assertRaises(ValueError):
                    PrivateCRIRPCConnection(clients[1], **arguments)
                self.assertEqual(clients[1].fileno(), -1)
                transport = PrivateCRIRPCConnection(clients[0], proc_view=view, **arguments)
                self.addCleanup(transport.close)
                servers[0].sendall(b'private-response')
                self.assertEqual(transport.receive(), b'private-response')
                self.assertEqual(transport.send(b'private-request'), 15)
                self.assertEqual(servers[0].recv(32), b'private-request')
                view.close()
                self.assertFalse(guard(servers[0], 5))
                with self.assertRaises(ValueError):
                    transport.send(b'must-not-send')
                self.assertEqual(transport.summary()['sent_bytes'], 15)
                self.assertTrue(transport.summary()['descriptors_closed'])
                self.assertTrue(transport.summary()['dependents_invalidated'])
                self.assertEqual(len(invalidations), 2)
            finally:
                os.fchdir(root); os.chroot('.'); os.fchdir(cwd)
                os.close(root); os.close(cwd)
