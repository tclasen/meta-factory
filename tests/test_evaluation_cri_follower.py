"""Actual Linux event/FD collection must refuse ambiguous or corrupted history."""
import os
from pathlib import Path
import sys
import struct
import tempfile
import time
import unittest
from unittest.mock import patch

from evaluation.cri_follower import LinuxCRIFollower, OVERFLOW
from evaluation.log_retention import PrivateCRIRetention


BINDING = dict(name='incident-app',uid='namespace-uid')
SOURCE = dict(namespace='incident-app',pod_name='api',pod_uid='pod-uid',container_name='runtime',container_id='containerd://one',previous=False)
CANARY = b'private\x00\xff-follower\narchive'


def frame(payload, tag=b'F'):
    return b'2026-10-05T12:30:45.123456789Z stdout '+tag+b' '+payload+b'\n'


@unittest.skipUnless(sys.platform.startswith('linux'), 'Node-local Linux inotify required')
class CRIFollowerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name);self.path = self.directory/'0.log'
        self.writer = self.path.open('wb', buffering=0);self.addCleanup(self.writer.close)
        self.retention = PrivateCRIRetention(BINDING);self.addCleanup(self.retention.close)
        self.allowed = True
        self.follower = None

    def follow(self, **options):
        self.follower = LinuxCRIFollower(self.retention, SOURCE, self.directory, '0.log',
            node_uid='node-uid',check=lambda *args:self.allowed,deadline=time.monotonic()+60,**options)
        self.addCleanup(self.follower.close)
        return self.follower

    def rotate(self, suffix='1', close_old=True):
        old = self.writer;self.path.rename(self.path.with_name('0.log.'+suffix))
        self.writer = self.path.open('wb', buffering=0);self.addCleanup(self.writer.close)
        if close_old:old.close()
        return old

    def test_growing_partial_frames_rotation_and_late_canary(self):
        follower=self.follow()
        raw=frame(CANARY.split(b'\n')[0][:8], b'P')
        self.writer.write(raw[:11]);follower.poll()
        self.writer.write(raw[11:]);follower.poll()
        self.rotate();self.writer.write(frame(CANARY.split(b'\n')[0][8:])+frame(CANARY.split(b'\n')[1]))
        receipt=follower.poll()
        self.assertEqual(receipt['rotations'],1)
        self.assertFalse(receipt['history_complete'])
        self.assertTrue(self.retention.inspect(binary_values=[CANARY])['canary_present'])
        self.assertNotIn(CANARY.hex(),repr(receipt))
        self.assertTrue(follower.close()['descriptors_closed'])
        self.assertFalse(self.retention.inspect(binary_values=[CANARY])['retention_valid'])
        self.assertTrue(self.retention.inspect(binary_values=[CANARY])['canary_present'])

    def test_old_descriptor_collects_late_growth_before_writer_closes(self):
        follower=self.follow();self.writer.write(frame(b'ordinary'));follower.poll()
        old=self.rotate(close_old=False)
        self.writer.write(frame(b'new-generation'))
        self.assertEqual(follower.poll()['rotations'],0)
        old.write(frame(b'private-late-old-canary'));old.close()
        self.assertEqual(follower.poll()['rotations'],1)
        self.assertTrue(self.retention.inspect(['private-late-old-canary'])['canary_present'])

    def test_unlinked_open_descriptor_keeps_receiving_growth(self):
        follower=self.follow();self.writer.write(frame(b'ordinary'));follower.poll()
        self.path.unlink();self.writer.write(frame(b'private-unlinked-canary'))
        follower.poll()
        self.assertTrue(self.retention.inspect(['private-unlinked-canary'])['canary_present'])

    def test_retired_growth_outside_watched_directory_invalidates_collection(self):
        remaining=self.path.open('r+b',buffering=0);self.addCleanup(remaining.close)
        follower=self.follow();self.writer.write(frame(b'private-prior-canary'));follower.poll()
        self.rotate();self.assertEqual(follower.poll()['rotations'],1)
        with tempfile.TemporaryDirectory() as outside:
            (self.directory/'0.log.1').rename(Path(outside)/'moved.log')
            remaining.seek(0,os.SEEK_END);remaining.write(frame(b'private-late-canary'))
            with self.assertRaisesRegex(ValueError,'^Private CRI collection unavailable$'):
                follower.poll()
        receipt=self.retention.inspect(['private-prior-canary'])
        self.assertTrue(receipt['canary_present']);self.assertFalse(receipt['retention_valid'])
        self.assertFalse(self.retention.inspect(['private-late-canary'])['canary_present'])
        self.assertTrue(follower.close()['descriptors_closed'])

    def test_retired_same_size_rewrite_outside_watch_invalidates_collection(self):
        remaining=self.path.open('r+b',buffering=0);self.addCleanup(remaining.close)
        follower=self.follow();raw=frame(b'private-prior-canary')
        self.writer.write(raw);follower.poll();self.rotate();follower.poll()
        with tempfile.TemporaryDirectory() as outside:
            (self.directory/'0.log.1').rename(Path(outside)/'moved.log')
            remaining.seek(0);remaining.write(b'x'*len(raw))
            with self.assertRaisesRegex(ValueError,'^Private CRI collection unavailable$'):
                follower.poll()
        receipt=self.retention.inspect(['private-prior-canary'])
        self.assertTrue(receipt['canary_present']);self.assertFalse(receipt['retention_valid'])
        self.assertTrue(follower.close()['descriptors_closed'])

    def test_stable_unlinked_retired_descriptor_is_held_until_cleanup(self):
        follower=self.follow();self.writer.write(frame(b'private-prior-canary'));follower.poll()
        self.rotate();follower.poll()
        retired=follower._retired['0.log.1']['fd']
        (self.directory/'0.log.1').unlink()
        self.assertEqual(follower.poll()['rotations'],1)
        self.assertEqual(os.fstat(retired).st_nlink,0)
        self.assertTrue(self.retention.inspect(['private-prior-canary'])['retention_valid'])
        self.assertTrue(follower.close()['descriptors_closed'])
        with self.assertRaises(OSError):os.fstat(retired)

    def test_reused_retired_name_refuses_and_closes_prior_descriptors(self):
        follower=self.follow();self.writer.write(frame(b'private-prior-canary'));follower.poll()
        self.rotate();follower.poll()
        retired=follower._retired['0.log.1']['fd']
        current=follower._current['fd']
        self.rotate()
        with self.assertRaises(ValueError):follower.poll()
        self.assertTrue(follower.close()['descriptors_closed'])
        for descriptor in (retired,current):
            with self.assertRaises(OSError):os.fstat(descriptor)
        receipt=self.retention.inspect(['private-prior-canary'])
        self.assertTrue(receipt['canary_present']);self.assertFalse(receipt['retention_valid'])

    def test_actual_rotation_limit_retains_and_closes_every_generation(self):
        follower=self.follow();self.writer.write(frame(b'private-prior-canary'));follower.poll()
        for index in range(128):
            self.rotate(str(index+1))
            self.assertEqual(follower.poll()['rotations'],index+1)
        descriptors=[state['fd'] for state in follower._retired.values()]
        self.assertEqual(len(descriptors),128)
        for descriptor in descriptors:os.fstat(descriptor)
        descriptors.append(follower._current['fd'])
        self.rotate('129')
        with self.assertRaises(ValueError):follower.poll()
        self.assertTrue(follower.close()['descriptors_closed'])
        for descriptor in descriptors:
            with self.assertRaises(OSError):os.fstat(descriptor)
        receipt=self.retention.inspect(['private-prior-canary'])
        self.assertTrue(receipt['canary_present']);self.assertFalse(receipt['retention_valid'])

    def test_same_size_overwrite_or_truncation_invalidates_without_erasing_positive(self):
        for corruption in ('rewrite','truncate'):
            with self.subTest(corruption=corruption), tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'0.log';raw=frame(b'private-prefix-canary');path.write_bytes(raw)
                retained=PrivateCRIRetention(BINDING)
                follower=LinuxCRIFollower(retained,SOURCE,directory,'0.log',node_uid='node-uid',check=lambda *args:True,deadline=time.monotonic()+60)
                try:
                    follower.poll()
                    path.write_bytes(b'x'*len(raw) if corruption=='rewrite' else b'')
                    with self.assertRaisesRegex(ValueError,'^Private CRI collection unavailable$'):follower.poll()
                    self.assertFalse(retained.inspect(['private-prefix-canary'])['retention_valid'])
                    self.assertTrue(retained.inspect(['private-prefix-canary'])['canary_present'])
                    self.assertTrue(follower.close()['descriptors_closed'])
                finally:follower.close();retained.close()

    def test_multiple_pending_rotations_are_incomplete_and_cleanup_is_verified(self):
        follower=self.follow();self.writer.write(frame(b'private-retained-canary'));follower.poll()
        self.rotate('1');self.writer.write(frame(b'first'))
        self.rotate('2');self.writer.write(frame(b'second'))
        with self.assertRaises(ValueError):follower.poll()
        self.assertTrue(follower.close()['descriptors_closed'])
        receipt=self.retention.inspect(['private-retained-canary'])
        self.assertTrue(receipt['canary_present']);self.assertFalse(receipt['retention_valid'])

    def test_replacement_symlink_prior_generation_and_late_retired_write_refused(self):
        follower=self.follow();self.writer.write(frame(b'ordinary'));follower.poll()
        self.rotate();follower.poll()
        with (self.directory/'0.log.1').open('ab') as retired:retired.write(frame(b'late'))
        with self.assertRaises(ValueError):follower.poll()
        follower.close()
        for mode in ('symlink','prior','fifo'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'0.log'
                if mode=='symlink':path.symlink_to(self.path)
                elif mode=='fifo':os.mkfifo(path)
                else:path.write_bytes(b'');path.with_name('0.log.older').write_bytes(b'')
                retained=PrivateCRIRetention(BINDING)
                try:
                    with self.assertRaisesRegex(ValueError,'^Private CRI follower unavailable$'):
                        LinuxCRIFollower(retained,SOURCE,directory,'0.log',node_uid='node-uid',check=lambda *args:True,deadline=time.monotonic()+60)
                    self.assertFalse(retained.inspect(['absent-canary'])['retention_valid'])
                finally:retained.close()

    def test_event_overflow_lost_guard_deadline_and_parent_bounds_refuse(self):
        for condition in ('overflow','guard','deadline','polls'):
            with self.subTest(condition=condition), tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'0.log';path.write_bytes(frame(b'private-bound-canary'))
                retained=PrivateCRIRetention(BINDING);allowed=[True]
                follower=LinuxCRIFollower(retained,SOURCE,directory,'0.log',node_uid='node-uid',check=lambda *args:allowed[0],deadline=time.monotonic()+60)
                try:
                    follower.poll()
                    descriptors=(follower._dir_fd,follower._notify_fd,follower._current['fd'])
                    if condition=='guard':allowed[0]=False
                    context=patch('evaluation.cri_follower.os.read',return_value=struct.pack('iIII',-1,OVERFLOW,0,0)) if condition=='overflow' else patch('evaluation.cri_follower.time.monotonic',return_value=float('inf')) if condition=='deadline' else patch('evaluation.cri_follower.MAX_POLLS',1) if condition=='polls' else patch('evaluation.cri_follower.MAX_POLLS',4096)
                    with context,self.assertRaises(ValueError):follower.poll()
                    self.assertFalse(retained.inspect(['private-bound-canary'])['retention_valid'])
                    self.assertTrue(follower.close()['descriptors_closed'])
                    for descriptor in descriptors:
                        with self.assertRaises(OSError):os.fstat(descriptor)
                finally:follower.close();retained.close()
        follower=self.follow()
        with patch('evaluation.cri_follower.os.getpid',return_value=-1),self.assertRaises(ValueError):follower.poll()
        self.assertEqual(follower.poll()['polls'],1)


if __name__=='__main__':unittest.main()
