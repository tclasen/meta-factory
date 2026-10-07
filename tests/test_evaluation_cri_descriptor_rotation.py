"""Successor admission cannot drop retired checks or erase prior captured positives."""
import os
import sys
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from evaluation.cri_follower import LinuxCRIDescriptorFollower
from evaluation.log_retention import PrivateCRIRetention
from test_evaluation_cri_follower import BINDING,SOURCE,frame


@unittest.skipUnless(sys.platform.startswith('linux'), 'Node-local Linux descriptors required')
class DescriptorRotationTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.old=Path(self.temp.name)/'old';self.new=Path(self.temp.name)/'new'
        self.old.write_bytes(frame(b'old-positive'));self.new.write_bytes(frame(b'new-positive'))
        self.oldfd=os.open(self.old,os.O_RDONLY);self.newfd=os.open(self.new,os.O_RDONLY)
        self.addCleanup(os.close,self.oldfd);self.addCleanup(os.close,self.newfd)
        self.retention=PrivateCRIRetention(BINDING);self.addCleanup(self.retention.close)
        self.follower=LinuxCRIDescriptorFollower(self.retention,SOURCE,self.oldfd,node_uid='node-uid',
            check=lambda *args:True,deadline=time.monotonic()+60)
        self.addCleanup(self.follower.close)

    def test_independent_successor_keeps_unlinked_old_fd_and_captures_both_files(self):
        self.follower.poll();self.old.unlink()
        self.assertEqual(self.follower.rotate(self.newfd,check=lambda *args:True)['rotations'],1)
        self.follower.poll()
        self.assertTrue(self.retention.inspect(['old-positive','new-positive'])['canary_present'])
        self.assertEqual(self.retention.inspect(['old-positive'])['files'],2)
        self.assertEqual(len(self.follower._retired),1)
        self.assertFalse(self.follower.poll()['history_complete'])
        self.assertTrue(self.follower.close()['descriptors_closed'])
        os.fstat(self.oldfd);os.fstat(self.newfd)

    def test_late_retired_growth_refuses_after_replacement(self):
        self.follower.rotate(self.newfd,check=lambda *args:True)
        retired=next(iter(self.follower._retired.values()))['fd']
        with self.old.open('ab') as writer:writer.write(frame(b'late-unseen'))
        with self.assertRaises(ValueError):self.follower.poll()
        with self.assertRaises(OSError):os.fstat(retired)
        self.assertTrue(self.retention.inspect(['old-positive'])['canary_present'])
        self.assertFalse(self.retention.inspect(['old-positive'])['retention_valid'])

    def test_retired_same_size_rewrite_refuses_and_preserves_captured_positive(self):
        self.follower.rotate(self.newfd,check=lambda *args:True)
        captured_size=self.old.stat().st_size
        replacement=frame(b'bad-positive')
        self.assertEqual(len(replacement),captured_size)
        self.old.write_bytes(replacement)
        with self.assertRaises(ValueError):self.follower.poll()
        self.assertTrue(self.retention.inspect(['old-positive'])['canary_present'])
        self.assertFalse(self.retention.inspect(['old-positive'])['retention_valid'])
        self.assertTrue(self.follower.close()['descriptors_closed'])

    def test_same_inode_writable_and_unobserved_boundary_refuse(self):
        self.follower.poll()
        with self.assertRaises(ValueError):self.follower.rotate(self.oldfd,check=lambda *args:True)
        self.assertFalse(self.retention.inspect(['old-positive'])['retention_valid'])
        for writable in (True,False):
            retention=PrivateCRIRetention(BINDING)
            f=LinuxCRIDescriptorFollower(retention,SOURCE,self.oldfd,node_uid='node-uid',
                check=lambda *args:True,deadline=time.monotonic()+60)
            descriptor=os.open(self.new,os.O_RDWR if writable else os.O_RDONLY)
            try:
                with self.assertRaises(ValueError):f.rotate(descriptor,check=lambda *args:writable)
                self.assertTrue(f.close()['descriptors_closed'])
            finally:os.close(descriptor);retention.close()

    def test_old_boundary_change_during_callback_refuses_and_preserves_prefix(self):
        self.follower.poll()
        def changed(proof,reserve):
            with self.old.open('ab') as writer:writer.write(frame(b'changed'))
            return True
        with self.assertRaises(ValueError):self.follower.rotate(self.newfd,check=changed)
        self.assertTrue(self.retention.inspect(['old-positive'])['canary_present'])
        self.assertFalse(self.retention.inspect(['old-positive'])['retention_valid'])

    def test_rotation_cap_refuses_before_admitting_successor(self):
        self.follower.poll()
        with patch('evaluation.cri_follower.MAX_ROTATIONS',0):
            with self.assertRaises(ValueError):self.follower.rotate(self.newfd,check=lambda *args:True)
        self.assertTrue(self.follower.close()['descriptors_closed'])
