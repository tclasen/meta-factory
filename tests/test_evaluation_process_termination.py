"""Pidfd-only termination refuses changed identity, revoked authority and late results."""
import os
import signal
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from evaluation.process_termination import process_identity, terminate_process


class ProcessTerminationTest(unittest.TestCase):
    def setUp(self):
        self.binding = dict(pid=912345, start_ticks=42, uid=10001, gid=10001,
            exe_device=1, exe_inode=2, pid_namespace_device=3, pid_namespace_inode=4,
            mount_namespace_device=5, mount_namespace_inode=6, cgroup_sha256='a'*64)
        self.enterContext(patch('evaluation.process_termination.sys.platform', 'linux'))
        self.open = self.enterContext(patch('evaluation.process_termination.os.pidfd_open', return_value=123, create=True))
        self.send = self.enterContext(patch('evaluation.process_termination.signal.pidfd_send_signal', create=True))
        self.close = self.enterContext(patch('evaluation.process_termination.os.close'))
        self.identity = self.enterContext(patch('evaluation.process_termination.process_identity', return_value=self.binding))
        self.poll = self.enterContext(patch('evaluation.process_termination.select.select', side_effect=[([], [], []), ([123], [], [])]))

    def terminate(self, **options):
        return terminate_process(self.binding, check=options.pop('check', lambda reserve: True),
            monotonic_deadline=options.pop('monotonic_deadline', time.monotonic()+60),
            wall_deadline=time.time()+60, **options)

    def test_signal_uses_only_pinned_descriptor_and_exit_is_required(self):
        result = self.terminate()
        self.assertEqual(result['outcome'], 'process_terminated')
        self.send.assert_called_once_with(123, signal.SIGKILL, None, 0)
        self.close.assert_called_once_with(123)

    def test_every_changed_identity_field_refuses_before_signal(self):
        for field in self.binding:
            with self.subTest(field=field):
                changed = dict(self.binding)
                changed[field] = 'b'*64 if field == 'cgroup_sha256' else changed[field]+1
                self.identity.return_value = changed
                with self.assertRaises(ValueError): self.terminate()
        self.send.assert_not_called()

    def test_revocation_after_open_refuses_and_closes_descriptor(self):
        values = iter((True, False))
        with self.assertRaises(ValueError): self.terminate(check=lambda reserve: next(values))
        self.send.assert_not_called(); self.close.assert_called_once_with(123)

    def test_post_signal_revocation_cannot_return_success(self):
        values = iter((True, True, False))
        with self.assertRaises(ValueError): self.terminate(check=lambda reserve: next(values))
        self.send.assert_called_once(); self.close.assert_called_once_with(123)

    def test_changed_identity_during_authorization_refuses(self):
        self.identity.side_effect = [dict(self.binding), dict(self.binding, start_ticks=43)]
        with self.assertRaises(ValueError): self.terminate()
        self.send.assert_not_called()

    def test_already_exited_process_cannot_be_a_successful_fault(self):
        self.poll.side_effect = [([123], [], [])]
        with self.assertRaises(ValueError): self.terminate()
        self.send.assert_not_called()

    def test_self_init_invalid_timeout_and_expired_lifetime_refuse(self):
        for value in (0, -1, True, float('nan'), 11):
            with self.subTest(timeout=value), self.assertRaises(ValueError): self.terminate(timeout=value)
        for value in (1, os.getpid()):
            original = self.binding['pid']; self.binding['pid'] = value
            with self.assertRaises(ValueError): self.terminate()
            self.binding['pid'] = original
        with self.assertRaises(ValueError): self.terminate(monotonic_deadline=time.monotonic()-1)
        self.open.assert_not_called()

    def test_callback_exception_is_redacted_and_does_not_signal(self):
        def broken(reserve): raise RuntimeError('private-process-canary')
        with self.assertRaisesRegex(ValueError, '^Process termination unavailable$'): self.terminate(check=broken)
        self.send.assert_not_called()


@unittest.skipUnless(sys.platform.startswith('linux') and hasattr(os, 'pidfd_open')
                    and hasattr(signal, 'pidfd_send_signal'), 'Linux pidfd controls')
class NativeProcessTerminationTest(unittest.TestCase):
    def child(self):
        child = subprocess.Popen([sys.executable, '-I', '-S', '-c',
            "import time; print('ready', flush=True); time.sleep(30)"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def cleanup():
            if child.poll() is None: child.kill()
            child.communicate(timeout=5)
        self.addCleanup(cleanup)
        self.assertEqual(child.stdout.readline(), b'ready\n')
        return child

    def test_actual_owned_child_exits_on_pinned_signal(self):
        child = self.child(); binding = process_identity(child.pid)
        owner = os.getpid()
        result = terminate_process(binding, check=lambda reserve: os.getpid() == owner and child.pid == binding['pid'],
            monotonic_deadline=time.monotonic()+10, wall_deadline=time.time()+10)
        self.assertTrue(result['process_exit_verified'])
        self.assertEqual(child.wait(timeout=5), -signal.SIGKILL)

    def test_mismatched_same_uid_child_survives_refused_signal(self):
        child = self.child(); binding = process_identity(child.pid)
        binding['start_ticks'] += 1
        with self.assertRaises(ValueError):
            terminate_process(binding, check=lambda reserve: True,
                monotonic_deadline=time.monotonic()+10, wall_deadline=time.time()+10)
        self.assertIsNone(child.poll())
