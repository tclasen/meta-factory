"""Late attribution must preserve early bytes without inventing a container ID."""
import copy
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from evaluation.cri_staging import PrivateCRIStaging, provisional_entry
from evaluation.cri_follower import LinuxCRIFollower
from evaluation.log_retention import PrivateCRIRetention
from test_evaluation_cri_follower import BINDING, SOURCE, frame


ENTRY = {key:SOURCE[key] for key in ('namespace','pod_name','pod_uid','container_name')} | dict(restart_index=0)
CANARY = b'private-staged\x00\xff-canary'


@unittest.skipUnless(sys.platform.startswith('linux'), 'Actual Linux file/event staging')
class CRIStagingTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.allowed=True;self.proofs=[]
        self.retention=PrivateCRIRetention(BINDING);self.addCleanup(self.retention.close)
        self.manager=PrivateCRIStaging(self.retention,check=lambda reserve:self.allowed,deadline=time.monotonic()+90)
        self.addCleanup(self.manager.close)

    def stage(self, entry=ENTRY, payload=CANARY):
        directory=self.root/entry['pod_uid'];directory.mkdir(exist_ok=True)
        path=directory/(str(entry['restart_index'])+'.log')
        writer=path.open('wb',buffering=0);self.addCleanup(writer.close)
        writer.write(frame(payload))
        self.manager.stage(entry,directory,node_uid='node-uid',check=lambda entry,reserve:self.allowed)
        return path,writer

    def binding(self, proof, reserve):
        self.proofs.append(copy.deepcopy(proof))
        return self.allowed

    def bind(self, entry=ENTRY, source=SOURCE):
        return self.manager.bind(entry,source,check=self.binding)

    def test_early_bytes_unlinked_before_cid_are_bound_and_later_growth_still_collected(self):
        path,writer=self.stage()
        receipt=self.manager.summary()
        self.assertEqual((receipt['unbound_sources'],receipt['bound_sources']),(1,0))
        self.assertFalse(self.retention.inspect(binary_values=[CANARY])['canary_present'])
        self.assertEqual(self.retention.inspect(binary_values=[CANARY])['sources'],0)
        self.assertNotIn('container_id',repr(self.manager.pending()))
        self.assertNotIn(CANARY.hex(),repr(receipt))
        path.unlink();writer.write(frame(b'before-CID-observation'));self.manager.poll()
        self.assertEqual(self.bind()['bound_sources'],1)
        self.assertTrue(self.retention.inspect(binary_values=[CANARY])['canary_present'])
        self.assertEqual(self.manager.pending(),[])
        self.assertEqual(self.manager.summary()['staged_bytes'],0)
        self.assertEqual(self.proofs[0]['entry']['restart_index'],0)
        self.assertEqual(self.proofs[0]['source'],SOURCE)
        self.assertEqual(self.proofs[0]['files'][0]['node_uid'],'node-uid')
        writer.write(frame(b'after-late-binding'));self.manager.poll()
        self.assertTrue(self.retention.inspect(['after-late-binding'])['canary_present'])
        closed=self.manager.close();self.assertTrue(closed['descriptors_closed'])
        self.assertTrue(self.retention.inspect(binary_values=[CANARY])['canary_present'])
        self.assertFalse(self.retention.inspect(binary_values=[CANARY])['retention_valid'])

    def test_rotations_before_and_after_binding_keep_exact_generation_order(self):
        path,writer=self.stage(payload=b'early-prefix')
        path.rename(path.with_name('0.log.1'));new=path.open('wb',buffering=0);self.addCleanup(new.close)
        writer.write(frame(CANARY));writer.close();new.write(frame(b'second'))
        self.manager.poll();self.assertEqual(len(self.manager.pending()[0]['files']),2)
        self.bind();self.assertTrue(self.retention.inspect(binary_values=[CANARY])['canary_present'])
        path.rename(path.with_name('0.log.2'));last=path.open('wb',buffering=0);self.addCleanup(last.close)
        new.close();last.write(frame(b'after-bound-rotation'))
        self.manager.poll()
        result=self.retention.inspect(['after-bound-rotation'])
        self.assertTrue(result['canary_present']);self.assertEqual(result['files'],3)
        self.assertFalse(result['history_complete'])

    def test_two_entries_share_staged_and_authoritative_byte_cap(self):
        path,writer=self.stage(payload=b'first-staged-canary')
        other=dict(ENTRY,pod_uid='another-pod')
        self.stage(other,payload=b'second-staged-canary')
        first=self.manager.summary()['staged_bytes'];self.bind()
        self.assertEqual(self.manager.summary()['staged_bytes']+self.retention._bytes,first)
        self.retention._max_bytes=first+5
        writer.write(frame(b'too-large'))
        with self.assertRaises(ValueError):self.manager.poll()
        self.assertTrue(self.manager.close()['descriptors_closed'])
        self.assertTrue(self.retention.inspect(['first-staged-canary'])['canary_present'])
        self.assertFalse(self.retention.inspect(['first-staged-canary'])['retention_valid'])

    def test_bad_late_binding_never_attests_unbound_canary_and_closes_descriptors(self):
        for mode in ('namespace','pod','uid','container','index','unknown','guard','duplicate'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'0.log';path.write_bytes(frame(CANARY))
                retention=PrivateCRIRetention(BINDING)
                manager=PrivateCRIStaging(retention,check=lambda reserve:True,deadline=time.monotonic()+90)
                try:
                    manager.stage(ENTRY,directory,node_uid='node-uid',check=lambda *args:True)
                    f=next(iter(manager._followers.values()));fds=(f._dir_fd,f._notify_fd,f._current['fd'])
                    source=dict(SOURCE);entry=dict(ENTRY)
                    if mode=='namespace':source['namespace']='foreign'
                    if mode=='pod':source['pod_name']='foreign'
                    if mode=='uid':source['pod_uid']='foreign'
                    if mode=='container':source['container_name']='foreign'
                    if mode=='index':entry['restart_index']=1
                    if mode=='unknown':entry['pod_uid']='unknown'
                    if mode=='duplicate':manager.bind(ENTRY,SOURCE,check=lambda *args:True)
                    with self.assertRaisesRegex(ValueError,'^Private CRI staging binding unavailable$'):
                        manager.bind(entry,source,check=lambda *args:mode!='guard')
                    for fd in fds:
                        with self.assertRaises(OSError):os.fstat(fd)
                    self.assertEqual(retention.inspect(binary_values=[CANARY])['canary_present'],mode=='duplicate')
                    self.assertFalse(retention.inspect(binary_values=[CANARY])['retention_valid'])
                finally:manager.close();retention.close()

    def test_binding_guard_is_rechecked_during_replay_and_later_quiet_polls(self):
        self.stage();calls=[]
        def denied_after_open(proof,reserve):
            calls.append(proof);return len(calls)<3
        with self.assertRaises(ValueError):self.manager.bind(ENTRY,SOURCE,check=denied_after_open)
        self.assertFalse(self.retention.inspect(binary_values=[CANARY])['canary_present'])
        self.assertTrue(self.manager.close()['descriptors_closed'])
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'0.log';path.write_bytes(frame(CANARY))
            r=PrivateCRIRetention(BINDING);m=PrivateCRIStaging(r,check=lambda reserve:True,deadline=time.monotonic()+90)
            allowed=[True]
            try:
                m.stage(ENTRY,directory,node_uid='node-uid',check=lambda *args:True)
                m.bind(ENTRY,SOURCE,check=lambda *args:allowed[0]);allowed[0]=False
                with self.assertRaises(ValueError):m.poll()
                self.assertTrue(r.inspect(binary_values=[CANARY])['canary_present'])
                self.assertFalse(r.inspect(binary_values=[CANARY])['retention_valid'])
            finally:m.close();r.close()

    def test_provisional_input_copies_and_no_pid_lock_or_dedicated_retention_bypass(self):
        self.stage();private=self.manager.pending();private[0]['entry']['pod_uid']='tampered'
        self.assertEqual(self.manager.pending()[0]['entry'],ENTRY)
        self.assertNotIn('container_id',repr(self.manager._slots))
        with patch('evaluation.cri_staging.os.getpid',return_value=-1):
            for operation in (self.manager.summary,self.manager.pending,self.manager.poll,self.manager.close):
                with self.assertRaises(ValueError):operation()
        with self.assertRaises(ValueError):provisional_entry(dict(ENTRY,container_id='fake'))
        with self.assertRaises(ValueError):provisional_entry(dict(ENTRY,restart_index=True))
        with self.assertRaises(ValueError):LinuxCRIFollower(self.retention,ENTRY,self.root,'0.log',
            node_uid='node-uid',check=lambda *args:True,deadline=time.monotonic()+90)
        self.bind()
        with self.assertRaises(ValueError):PrivateCRIStaging(self.retention,check=lambda reserve:True,deadline=time.monotonic()+90)

    def test_lost_global_guard_deadline_corruption_and_entry_bounds_fail_closed(self):
        for mode in ('guard','deadline','corruption','entries','operations'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'0.log';path.write_bytes(frame(CANARY))
                r=PrivateCRIRetention(BINDING);allowed=[True]
                m=PrivateCRIStaging(r,check=lambda reserve:allowed[0],deadline=time.monotonic()+90)
                try:
                    m.stage(ENTRY,directory,node_uid='node-uid',check=lambda *args:True)
                    if mode=='guard':allowed[0]=False
                    if mode=='deadline':m._deadline=time.monotonic()
                    if mode=='corruption':path.write_bytes(b'x'*path.stat().st_size)
                    if mode=='operations':m._operations=65536;path.write_bytes(path.read_bytes()+frame(b'late'))
                    if mode=='entries':
                        with patch('evaluation.cri_staging.MAX_SOURCES',1),self.assertRaises(ValueError):
                            m.stage(dict(ENTRY,pod_uid='other'),directory,node_uid='node-uid',check=lambda *args:True)
                    else:
                        with self.assertRaises(ValueError):m.poll()
                    self.assertTrue(m.close()['descriptors_closed'])
                    self.assertFalse(r.inspect(binary_values=[CANARY])['canary_present'])
                finally:m.close();r.close()
