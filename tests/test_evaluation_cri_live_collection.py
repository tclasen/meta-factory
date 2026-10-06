"""Source refusal closes owned files but does not erase captured leak evidence."""
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

from evaluation.cri_live_collection import PrivateCRILiveCollection
from test_evaluation_cri_binding import ENTRY, NODE, pending_history
from test_evaluation_cri_follower import frame
from test_evaluation_cri_runtime_event import runtime_event


class LiveCollectionTest(unittest.TestCase):
    def setUp(self):
        self.history=pending_history();self.allowed=True;self.file_allowed=True
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.path=Path(self.directory.name)/'0.log';self.path.write_bytes(frame(b'private-positive\n'))
        self.fd=os.open(self.path,os.O_RDONLY);self.addCleanup(os.close,self.fd)
        self.collection=PrivateCRILiveCollection(self.history,node_uid='node-uid',node_name='node-1',
            check=lambda reserve:self.allowed,deadline=time.monotonic()+60)
        self.addCleanup(self.collection.release)

    def check(self, proof, reserve):
        observed=os.fstat(self.fd)
        return self.file_allowed and proof['entry']==ENTRY and proof['projection']['file_identity']==dict(node_uid='node-uid',device=observed.st_dev,inode=observed.st_ino)

    def admit(self):
        self.collection.feed(json.dumps(runtime_event()).encode())
        return self.collection.bind(ENTRY,NODE,self.fd,check=self.check)

    def positive(self):return self.collection.inspect(binary_values=[b'private-positive'])

    def test_live_metadata_binds_unlinked_initial_file_and_survives_window_end(self):
        self.assertEqual(self.admit()['bound_initial_files'],1)
        self.path.unlink();self.collection.poll()
        self.assertTrue(self.positive()['canary_present'])
        self.assertTrue(self.positive()['retention_valid'])
        self.collection.finish();self.collection.poll()
        self.assertFalse(self.collection.summary()['history_complete'])
        self.assertEqual(self.history.sources(),[])

    def test_truncated_source_closes_owned_fd_and_preserves_positive(self):
        self.admit();self.collection.poll()
        owned=next(iter(self.collection._followers.values()))._current['fd']
        self.collection.feed(b'{"private":')
        with self.assertRaisesRegex(ValueError,'^Private live collection unavailable$'):self.collection.finish()
        with self.assertRaises(OSError):os.fstat(owned)
        os.fstat(self.fd)  # Borrowed caller FD is still owned by its caller.
        self.assertTrue(self.positive()['canary_present']);self.assertFalse(self.positive()['retention_valid'])
        self.assertTrue(self.collection.summary()['metadata_released'])
        self.assertTrue(self.collection.summary()['descriptors_closed'])
        self.assertTrue(self.collection._archive.summary()['metadata_released'])
        self.assertTrue(self.collection._buffer.summary()['metadata_released'])

    def test_original_peer_and_file_guard_failure_preserve_existing_positive(self):
        self.admit();self.collection.poll();self.allowed=False
        with self.assertRaises(ValueError):self.collection.poll()
        self.assertTrue(self.positive()['canary_present']);self.assertFalse(self.positive()['retention_valid'])
        self.assertTrue(self.collection.summary()['descriptors_closed'])

    def test_later_file_guard_and_independent_dependency_loss_preserve_positive(self):
        self.admit();self.collection.poll();self.file_allowed=False
        with self.assertRaises(ValueError):self.collection.poll()
        self.assertTrue(self.positive()['canary_present']);self.assertFalse(self.positive()['retention_valid'])
        self.assertTrue(self.collection.summary()['descriptors_closed'])
        other=PrivateCRILiveCollection(pending_history(),node_uid='node-uid',node_name='node-1',
            check=lambda reserve:True,deadline=time.monotonic()+60)
        try:
            other._buffer.close()
            with self.assertRaises(ValueError):other.feed(json.dumps(runtime_event()).encode())
            self.assertTrue(other.summary()['metadata_released'])
        finally:other.release()

    def test_file_guard_failure_and_writable_descriptor_refuse_admission(self):
        self.collection.feed(json.dumps(runtime_event()).encode());self.file_allowed=False
        with self.assertRaises(ValueError):self.collection.bind(ENTRY,NODE,self.fd,check=self.check)
        self.assertTrue(self.collection.summary()['metadata_released'])
        other=PrivateCRILiveCollection(pending_history(),node_uid='node-uid',node_name='node-1',
            check=lambda reserve:True,deadline=time.monotonic()+60)
        writable=os.open(self.path,os.O_RDWR)
        try:
            other.feed(json.dumps(runtime_event()).encode())
            with self.assertRaises(ValueError):other.bind(ENTRY,NODE,writable,check=lambda *args:True)
            self.assertTrue(other.summary()['metadata_released'])
        finally:os.close(writable);other.release()

    def test_pending_metadata_and_duplicate_initial_binding_are_explicit(self):
        self.assertIsNone(self.collection.bind(ENTRY,NODE,self.fd,check=self.check))
        self.assertEqual(self.collection.summary()['bound_initial_files'],0)
        self.admit()
        with self.assertRaises(ValueError):self.collection.bind(ENTRY,NODE,self.fd,check=self.check)
        self.assertTrue(self.collection.summary()['descriptors_closed'])

    def test_guard_change_inside_transaction_refuses_all_admitted_metadata(self):
        original=self.collection._buffer.accept
        def changed(value):
            result=original(value);self.allowed=False;return result
        self.collection._decoder._consume=changed
        with self.assertRaises(ValueError):self.collection.feed(json.dumps(runtime_event()).encode())
        self.assertTrue(self.collection.summary()['metadata_released'])

    def test_no_child_scope_cache_outside_transaction_and_release_is_final(self):
        self.admit();self.collection.poll()
        self.assertFalse(self.collection._scope(5))
        self.collection.close()
        self.assertTrue(self.positive()['canary_present'])
        self.collection.release()
        with self.assertRaises(ValueError):self.positive()
        with self.assertRaises(ValueError):self.collection.poll()
