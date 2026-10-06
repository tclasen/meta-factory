"""Native-held successor bytes stay provisional until independent attribution."""
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

from evaluation.cri_staging import PrivateCRIStaging
from evaluation.log_retention import PrivateCRIRetention
from test_evaluation_cri_staging import ENTRY
from test_evaluation_cri_follower import BINDING, SOURCE, frame


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux held descriptors')
class StagingSuccessorTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.old=self.root/'old';self.new=self.root/'new'
        self.old.write_bytes(frame(b'early-positive'));self.new.write_bytes(frame(b'new-positive'))
        self.old_fd=os.open(self.old,os.O_RDONLY);self.new_fd=os.open(self.new,os.O_RDONLY)
        self.addCleanup(os.close,self.old_fd);self.addCleanup(os.close,self.new_fd)
        self.retention=PrivateCRIRetention(BINDING);self.addCleanup(self.retention.close)
        self.manager=PrivateCRIStaging(self.retention,check=lambda _:True,deadline=time.monotonic()+60)
        self.addCleanup(self.manager.close)
        self.manager.stage_descriptor(ENTRY,self.old_fd,node_uid='node-uid',check=lambda *args:True)

    def rotate(self,check=lambda *args:True,node_uid='node-uid'):
        return self.manager.rotate_descriptor(ENTRY,self.new_fd,node_uid=node_uid,check=check)

    def test_unlinked_successor_bytes_remain_unscannable_until_both_files_bound(self):
        self.old.unlink();self.new.unlink();proofs=[]
        def boundary(proof,reserve):proofs.append(proof);return True
        self.rotate(check=boundary)
        self.assertFalse(self.retention.inspect(['early-positive','new-positive'])['canary_present'])
        self.assertEqual(len(self.manager.pending()[0]['files']),2)
        self.assertEqual(proofs[0]['source'],ENTRY)
        observed=[]
        self.manager.bind(ENTRY,SOURCE,check=lambda proof,reserve:observed.append(proof) is None)
        self.assertTrue(all(len(proof['files'])==2 for proof in observed))
        self.assertTrue(self.retention.inspect(['new-positive'])['canary_present'])
        self.assertEqual(self.retention.inspect(['early-positive'])['files'],2)
        self.assertEqual(self.manager.summary()['staged_bytes'],0)
        self.assertFalse(self.manager.summary()['history_complete'])
        os.fstat(self.old_fd);os.fstat(self.new_fd)

    def test_bound_successor_revalidates_expanded_file_proof(self):
        counts=[]
        self.manager.bind(ENTRY,SOURCE,check=lambda proof,reserve:counts.append(len(proof['files'])) is None)
        self.rotate();self.manager.poll()
        self.assertIn(2,counts)
        self.assertTrue(self.retention.inspect(['new-positive'])['canary_present'])
        with self.old.open('ab') as writer:writer.write(frame(b'late-retired'))
        with self.assertRaises(ValueError):self.manager.poll()
        self.assertTrue(self.retention.inspect(['early-positive'])['canary_present'])
        self.assertFalse(self.retention.inspect(['early-positive'])['retention_valid'])
        self.assertTrue(self.manager.close()['descriptors_closed'])

    def test_binding_that_does_not_accept_successor_refuses_preserving_old_positive(self):
        self.manager.bind(ENTRY,SOURCE,check=lambda proof,reserve:len(proof['files'])==1)
        with self.assertRaises(ValueError):self.rotate()
        self.assertTrue(self.retention.inspect(['early-positive'])['canary_present'])
        self.assertFalse(self.retention.inspect(['early-positive'])['retention_valid'])
        self.assertTrue(self.manager.close()['descriptors_closed'])

    def test_cross_node_successor_refuses_and_discards_unbound_data(self):
        with self.assertRaises(ValueError):self.rotate(node_uid='other-node')
        self.assertTrue(self.manager.close()['descriptors_closed'])
        self.assertEqual(self.manager.summary()['staged_bytes'],0)
        self.assertFalse(self.retention.inspect(['early-positive'])['canary_present'])
