"""Received held descriptors preserve unlinked bytes without inventing coverage."""
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

from evaluation.cri_staging import PrivateCRIStaging
from evaluation.log_retention import PrivateCRIRetention
from test_evaluation_cri_follower import BINDING, SOURCE, frame
from test_evaluation_cri_staging import ENTRY


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux held descriptors')
class CRIDescriptorTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'0.log';self.path.write_bytes(frame(b'early-secret'))
        self.descriptor=os.open(self.path,os.O_RDONLY);self.addCleanup(os.close,self.descriptor)
        self.retention=PrivateCRIRetention(BINDING);self.addCleanup(self.retention.close)
        self.allowed=True
        self.manager=PrivateCRIStaging(self.retention,check=lambda reserve:self.allowed,deadline=time.monotonic()+90)
        self.addCleanup(self.manager.close)

    def stage(self, descriptor=None):
        return self.manager.stage_descriptor(ENTRY,self.descriptor if descriptor is None else descriptor,
            node_uid='node-uid',check=lambda entry,reserve:self.allowed)

    def bind(self):
        return self.manager.bind(ENTRY,SOURCE,check=lambda proof,reserve:self.allowed)

    def test_unlinked_before_staging_bytes_private_until_bound_then_growth_retained(self):
        with self.path.open('ab',buffering=0) as writer:
            self.path.unlink();self.stage()
            self.assertFalse(self.retention.inspect(['early-secret'])['canary_present'])
            self.assertNotIn('container_id',repr(self.manager.pending()))
            self.assertFalse(self.manager.summary()['history_complete'])
            self.bind();self.assertTrue(self.retention.inspect(['early-secret'])['canary_present'])
            writer.write(frame(b'late-secret'));self.manager.poll()
            self.assertTrue(self.retention.inspect(['late-secret'])['canary_present'])
        self.assertTrue(self.manager.close()['descriptors_closed'])
        self.assertTrue(self.retention.inspect(['early-secret'])['canary_present'])
        os.fstat(self.descriptor)

    def test_borrowed_offset_cloexec_and_caller_close(self):
        os.lseek(self.descriptor,7,os.SEEK_SET);self.stage()
        follower=next(iter(self.manager._followers.values()))
        self.assertFalse(os.get_inheritable(follower._current['fd']))
        self.assertEqual(os.lseek(self.descriptor,0,os.SEEK_CUR),7)
        # Close a separately borrowed handle without affecting the managed copy.
        borrowed=os.dup(self.descriptor)
        other_retention=PrivateCRIRetention(BINDING)
        other=PrivateCRIStaging(other_retention,check=lambda reserve:True,deadline=time.monotonic()+90)
        try:
            other.stage_descriptor(ENTRY,borrowed,node_uid='node-uid',check=lambda *args:True)
            os.close(borrowed);borrowed=None
            other.poll();other.bind(ENTRY,SOURCE,check=lambda *args:True)
            self.assertTrue(other_retention.inspect(['early-secret'])['canary_present'])
        finally:
            if borrowed is not None:os.close(borrowed)
            other.close();other_retention.close()

    def test_wrong_descriptor_modes_types_and_guard_fail_closed(self):
        for mode in ('writable','directory','pipe','opath','boolean','closed','guard'):
            with self.subTest(mode=mode):
                retention=PrivateCRIRetention(BINDING)
                manager=PrivateCRIStaging(retention,check=lambda reserve:True,deadline=time.monotonic()+90)
                owned=[]
                try:
                    descriptor=self.descriptor
                    if mode=='writable':descriptor=os.open(self.path,os.O_RDWR);owned.append(descriptor)
                    if mode=='directory':descriptor=os.open(self.temp.name,os.O_RDONLY);owned.append(descriptor)
                    if mode=='pipe':owned=list(os.pipe());descriptor=owned[0]
                    if mode=='opath':descriptor=os.open(self.path,os.O_PATH);owned.append(descriptor)
                    if mode=='boolean':descriptor=True
                    if mode=='closed':descriptor=os.open(self.path,os.O_RDONLY);os.close(descriptor)
                    with self.assertRaisesRegex(ValueError,'^Private CRI descriptor staging unavailable$'):
                        manager.stage_descriptor(ENTRY,descriptor,node_uid='node-uid',check=lambda *args:mode!='guard')
                    self.assertTrue(manager.summary()['descriptors_closed'])
                    self.assertFalse(retention.inspect(['early-secret'])['canary_present'])
                    os.fstat(self.descriptor)
                finally:
                    manager.close();retention.close()
                    for descriptor in owned:os.close(descriptor)

    def test_duplicate_entry_and_inode_are_refused(self):
        for same_entry in (True,False):
            with self.subTest(same_entry=same_entry):
                retention=PrivateCRIRetention(BINDING)
                manager=PrivateCRIStaging(retention,check=lambda reserve:True,deadline=time.monotonic()+90)
                try:
                    manager.stage_descriptor(ENTRY,self.descriptor,node_uid='node-uid',check=lambda *args:True)
                    entry=ENTRY if same_entry else dict(ENTRY,restart_index=1)
                    with self.assertRaises(ValueError):
                        manager.stage_descriptor(entry,self.descriptor,node_uid='node-uid',check=lambda *args:True)
                    self.assertTrue(manager.close()['descriptors_closed'])
                finally:manager.close();retention.close()

    def test_overwrite_and_truncation_after_binding_preserve_prior_positive(self):
        for truncate in (True,False):
            with self.subTest(truncate=truncate):
                self.path.write_bytes(frame(b'early-secret'))
                retention=PrivateCRIRetention(BINDING)
                manager=PrivateCRIStaging(retention,check=lambda reserve:True,deadline=time.monotonic()+90)
                try:
                    manager.stage_descriptor(ENTRY,self.descriptor,node_uid='node-uid',check=lambda *args:True)
                    manager.bind(ENTRY,SOURCE,check=lambda *args:True)
                    if truncate:self.path.write_bytes(b'')
                    else:
                        with self.path.open('r+b') as writer:writer.write(b'X')
                    with self.assertRaises(ValueError):manager.poll()
                    result=retention.inspect(['early-secret'])
                    self.assertTrue(result['canary_present']);self.assertFalse(result['retention_valid'])
                    self.assertTrue(manager.summary()['descriptors_closed'])
                finally:manager.close();retention.close()

    def test_guard_and_byte_cap_close_all_owned_descriptors(self):
        self.stage();self.bind()
        follower=next(iter(self.manager._followers.values()));owned=follower._current['fd']
        self.allowed=False
        with self.assertRaises(ValueError):self.manager.poll()
        with self.assertRaises(OSError):os.fstat(owned)
        self.assertTrue(self.retention.inspect(['early-secret'])['canary_present'])
        retention=PrivateCRIRetention(BINDING,max_bytes=5)
        manager=PrivateCRIStaging(retention,check=lambda reserve:True,deadline=time.monotonic()+90)
        try:
            with self.assertRaises(ValueError):manager.stage_descriptor(ENTRY,self.descriptor,node_uid='node-uid',check=lambda *args:True)
            self.assertTrue(manager.summary()['descriptors_closed'])
            self.assertFalse(retention.inspect(['early-secret'])['canary_present'])
        finally:manager.close();retention.close()
