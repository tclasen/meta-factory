"""Held runtime transport rejects substituted peers and dependent lifetime loss."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from evaluation.cri_events import linux_peer_identity
from evaluation.cri_rpc import PrivateCRIRPCConnection


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux runtime peer authentication')
class CRIRPCTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)/'runtime.sock'
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(self.listener.close)
        self.listener.bind(str(self.path))
        self.listener.listen(1)
        self.client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(self.client.close)
        self.client.settimeout(1)
        self.client.connect(str(self.path))
        self.server, _ = self.listener.accept()
        self.addCleanup(self.server.close)
        executable = os.stat('/proc/self/exe')
        endpoint = self.path.stat()
        self.peer = dict(uid=os.getuid(), gid=os.getgid(), **linux_peer_identity(os.getpid()),
                         exe_device=executable.st_dev, exe_inode=executable.st_ino,
                         socket_device=endpoint.st_dev, socket_inode=endpoint.st_ino)
        self.allowed = True
        self.invalidations = 0
        self.transport = self.admit(self.client)
        self.addCleanup(self.transport.close)

    def invalidate(self):
        self.invalidations += 1

    def admit(self, client, **overrides):
        arguments = dict(peer=self.peer, endpoint=str(self.path),
                         check=lambda reserve: self.allowed,
                         invalidate=self.invalidate, deadline=time.monotonic()+60)
        arguments.update(overrides)
        return PrivateCRIRPCConnection(client, **arguments)

    def test_actual_held_fd_io_and_idle_timeout_handoff(self):
        self.assertIsNone(self.client.gettimeout())
        started = time.monotonic()
        self.assertIsNone(self.transport.receive())
        self.assertLess(time.monotonic()-started, .5)
        self.server.sendall(b'private-response')
        self.assertEqual(self.transport.receive(), b'private-response')
        self.assertEqual(self.transport.send(b'private-request'), 15)
        self.assertEqual(self.server.recv(32), b'private-request')
        summary = self.transport.poll()
        self.assertEqual(summary['received_bytes'], 16)
        self.assertEqual(summary['sent_bytes'], 15)
        self.assertFalse(summary['history_complete'])
        self.assertNotIn('private', repr({k: v for k, v in summary.items() if k != 'outcome'}))

    def test_observed_socket_replacement_terminal_and_restore_cannot_revive(self):
        saved = self.path.with_suffix('.saved')
        self.path.rename(saved)
        replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(replacement.close)
        replacement.bind(str(self.path))
        with self.assertRaisesRegex(ValueError, '^Private runtime transport unavailable$'):
            self.transport.send(b'private-secret')
        self.assertEqual(self.transport.summary()['sent_bytes'], 0)
        self.assertTrue(self.transport.summary()['descriptors_closed'])
        self.assertEqual(self.invalidations, 1)
        self.path.unlink()
        saved.rename(self.path)
        with self.assertRaises(ValueError):
            self.transport.poll()
        self.transport.close()
        self.assertEqual(self.invalidations, 1)

    def test_unobserved_restored_swap_cannot_redirect_existing_fd(self):
        saved = self.path.with_suffix('.saved')
        self.path.rename(saved)
        replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(replacement.close)
        replacement.bind(str(self.path))
        self.path.unlink()
        saved.rename(self.path)
        self.server.sendall(b'original-held-peer')
        self.assertEqual(self.transport.receive(), b'original-held-peer')
        self.assertTrue(self.transport.poll()['valid'])

    def test_new_fd_wrong_same_uid_peer_rejected_after_path_restoration(self):
        saved = self.path.with_suffix('.saved')
        self.path.rename(saved)
        child = subprocess.Popen([sys.executable, '-c',
            'import socket,sys,time; s=socket.socket(socket.AF_UNIX); '
            's.bind(sys.argv[1]); s.listen(1); print("ready",flush=True); '
            'c,_=s.accept(); time.sleep(20)', str(self.path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(child.stdout.close)
        self.addCleanup(child.stderr.close)
        def cleanup():
            child.terminate()
            child.wait(timeout=5)
        self.addCleanup(cleanup)
        import select
        self.assertTrue(select.select([child.stdout], [], [], 3)[0])
        self.assertEqual(child.stdout.readline(), b'ready\n')
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(connection.close)
        connection.settimeout(2)
        connection.connect(str(self.path))
        self.path.unlink()
        saved.rename(self.path)
        with self.assertRaisesRegex(ValueError, '^Private runtime connection unavailable$'):
            self.admit(connection)
        self.assertEqual(connection.fileno(), -1)
        self.assertEqual(self.invalidations, 1)
        self.assertTrue(self.transport.poll()['valid'])

    def test_post_io_guard_failure_does_not_return_private_bytes(self):
        self.server.sendall(b'private-sensitive-response')
        checks = iter([True, False])
        self.transport._check = lambda reserve: next(checks)
        with self.assertRaises(ValueError):
            self.transport.receive()
        self.assertTrue(self.transport.summary()['descriptors_closed'])
        self.assertEqual(self.invalidations, 1)

    def test_unexpected_eof_refuses_and_invalidates_dependents(self):
        self.server.close()
        with self.assertRaises(ValueError):
            self.transport.receive()
        self.assertTrue(self.transport.summary()['dependents_invalidated'])
        self.assertFalse(self.transport.summary()['valid'])

    def test_expired_guard_no_request_sent(self):
        self.transport._deadline = time.monotonic()+4
        with self.assertRaises(ValueError):
            self.transport.send(b'private-secret')
        self.assertEqual(self.transport.summary()['sent_bytes'], 0)

    def test_aggregate_bound_refuses_before_send(self):
        with patch('evaluation.cri_rpc.MAX_TRAFFIC_BYTES', 5):
            self.assertEqual(self.transport.send(b'first'), 5)
            with self.assertRaises(ValueError):
                self.transport.send(b'next')
        self.assertEqual(self.transport.summary()['sent_bytes'], 5)

    def test_failed_dependent_cleanup_is_reported(self):
        self.transport._invalidate = lambda: (_ for _ in ()).throw(RuntimeError('private-secret'))
        self.allowed = False
        with self.assertRaisesRegex(ValueError, '^Private runtime transport unavailable$'):
            self.transport.poll()
        summary = self.transport.summary()
        self.assertTrue(summary['descriptors_closed'])
        self.assertFalse(summary['dependents_invalidated'])

    def test_bad_original_projection_closes_transferred_fd(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        peer = dict(self.peer, pid=True)
        with self.assertRaises(ValueError):
            self.admit(left, peer=peer)
        self.assertEqual(left.fileno(), -1)

    def test_original_executable_mismatch_refuses_actual_connection(self):
        self.transport._peer['exe_inode'] += 1
        with self.assertRaises(ValueError):
            self.transport.poll()
        self.assertTrue(self.transport.summary()['descriptors_closed'])

    def test_inherited_owner_cannot_operate_or_invalidate_original(self):
        with patch('evaluation.cri_rpc.os.getpid', return_value=os.getpid()+1):
            with self.assertRaisesRegex(ValueError, 'owner unavailable'):
                self.transport.send(b'private-secret')
        self.assertEqual(self.invalidations, 0)
        self.assertTrue(self.transport.poll()['valid'])

    def test_oversized_private_request_refuses_before_io(self):
        with self.assertRaises(ValueError):
            self.transport.send(b'x'*65537)
        self.assertEqual(self.transport.summary()['sent_bytes'], 0)
