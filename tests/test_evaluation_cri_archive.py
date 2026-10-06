"""Archived identity survives GC; unknown births and changed guards do not pass."""
import copy
import os
from pathlib import Path
import tempfile
import time
import sys
import unittest
from unittest.mock import patch

from evaluation.cri_archive import PrivateCRIRuntimeArchive
from evaluation.cri_staging import PrivateCRIStaging
from evaluation.log_retention import PrivateCRIRetention
from test_evaluation_cri_binding import (ENTRY, FILE, NODE, SOURCE, SECRET,
    pending_history, snapshots)
from test_evaluation_pod_history import BINDING, pod, event, receipt, history
from test_evaluation_cri_follower import frame
from test_evaluation_cri_runtime_event import runtime_event


class CRIArchiveTest(unittest.TestCase):
    def setUp(self):
        self.history=pending_history();self.allowed=True
        self.archive=PrivateCRIRuntimeArchive(self.history,node_uid='node-uid',
            node_name='node-1',check=lambda reserve:self.allowed,deadline=time.monotonic()+60)
        self.addCleanup(self.archive.close)

    def capture(self, **changes):
        values=dict(entry=ENTRY,node=NODE,snapshot=snapshots(),file_identity=FILE,check=lambda *args:True)
        values.update(changes);return self.archive.capture(**values)

    def resolve(self, **changes):
        values=dict(entry=ENTRY,file_identity=FILE,check=lambda *args:True)
        values.update(changes);return self.archive.resolve(**values)

    def test_event_metadata_archives_without_runtime_snapshot_requery(self):
        value=runtime_event()
        result=self.archive.capture_event(ENTRY,NODE,value,FILE,check=lambda *args:True)
        self.assertEqual(result['source'],SOURCE)
        value.clear()
        with patch('evaluation.cri_archive.bind_cri_log_source',side_effect=AssertionError('no requery')):
            self.assertEqual(self.resolve()['source'],SOURCE)
        self.assertNotIn(SECRET,repr(self.archive._records))
        self.assertFalse(self.archive.summary()['history_complete'])

    def test_deleted_event_never_creates_file_attribution(self):
        value=runtime_event('CONTAINER_DELETED_EVENT');value['containersStatuses']=[]
        self.assertIsNone(self.archive.capture_event(ENTRY,NODE,value,FILE,check=lambda *args:True))
        self.assertIsNone(self.resolve())
        self.assertEqual(self.archive.summary()['files'],0)
        self.assertTrue(self.archive.summary()['valid'])

    def test_event_failure_permanently_releases_prior_archive(self):
        self.capture()
        value=runtime_event();value['containersStatuses'][0]['logPath']='/foreign/0.log'
        with self.assertRaises(ValueError):
            self.archive.capture_event(ENTRY,NODE,value,FILE,check=lambda *args:True)
        self.assertTrue(self.archive.summary()['metadata_released'])
        with self.assertRaises(ValueError):self.resolve()

    def test_event_admission_uses_original_runtime_and_held_file_guards(self):
        for failure in ('runtime','file'):
            with self.subTest(failure=failure):
                archive=PrivateCRIRuntimeArchive(pending_history(),node_uid='node-uid',
                    node_name='node-1',check=lambda reserve:self.allowed,deadline=time.monotonic()+60)
                if failure=='runtime':self.allowed=False
                try:
                    with self.assertRaises(ValueError):
                        archive.capture_event(ENTRY,NODE,runtime_event(),FILE,check=lambda *args:failure!='file')
                    self.assertTrue(archive.summary()['metadata_released'])
                finally:
                    self.allowed=True;archive.close()

    def test_capture_then_deleted_pending_resolves_without_runtime_requery(self):
        before=self.history.summary();snapshot=snapshots();result=self.capture(snapshot=snapshot)
        self.assertEqual(result['source'],SOURCE);self.assertEqual(before,self.history.summary())
        snapshot.clear();result['source']['container_id']='tampered'
        start=self.history.begin();value=pod(uid=ENTRY['pod_uid']);value['status']={}
        self.history.accept(event(value,'DELETED'));self.history.finish(receipt(start,1))
        with patch('evaluation.cri_archive.bind_cri_log_source',side_effect=AssertionError('no runtime requery')):
            archived=self.resolve()
        self.assertEqual(archived['source'],SOURCE);self.assertTrue(archived['pod_deleted'])
        self.assertTrue(archived['api_pending']);self.assertFalse(archived['api_container_id_observed'])
        self.assertEqual(self.history.summary()['unresolved_deleted_containers'],1)
        self.assertFalse(self.archive.summary()['history_complete'])
        self.assertNotIn(SECRET,repr(self.archive._records));self.assertNotIn(SECRET,repr(archived))
        self.assertNotIn(ENTRY['pod_uid'],repr(self.archive.summary()))

    def test_unknown_entry_and_unobserved_generation_never_inherit_identity(self):
        self.assertIsNone(self.resolve());self.capture()
        self.assertIsNone(self.resolve(file_identity=dict(FILE,inode=2)))
        self.assertIsNone(self.capture(entry=dict(ENTRY,container_name='unknown')))
        self.assertEqual(self.archive.summary()['files'],1)
        self.assertTrue(self.archive.summary()['valid'])

    def test_independently_captured_generation_and_duplicate_keep_bounded_identity(self):
        self.capture();self.capture();self.capture(file_identity=dict(FILE,inode=2))
        self.assertEqual(self.archive.summary()['entries'],1)
        self.assertEqual(self.archive.summary()['files'],2)
        self.assertEqual(self.resolve(file_identity=dict(FILE,inode=2))['source'],SOURCE)

    def test_creation_and_sandbox_changes_discard_archive(self):
        for mode in ('container-time','sandbox-time','sandbox-id'):
            with self.subTest(mode=mode):
                archive=PrivateCRIRuntimeArchive(pending_history(),node_uid='node-uid',node_name='node-1',check=lambda *args:True,deadline=time.monotonic()+60)
                archive.capture(ENTRY,NODE,snapshots(),FILE,check=lambda *args:True)
                value=snapshots()
                if mode=='container-time':
                    value['container']['createdAt']=value['container_detail']['status']['createdAt']='1700000000000000002'
                elif mode=='sandbox-time':
                    value['sandbox']['createdAt']=value['sandbox_detail']['status']['createdAt']='1699999999999999999'
                else:
                    value['sandbox']['id']=value['sandbox_detail']['status']['id']='c'*64
                    value['container']['podSandboxId']=value['container_detail']['info']['sandboxID']='c'*64
                with self.assertRaisesRegex(ValueError,'^Private CRI runtime archive unavailable$'):
                    archive.capture(ENTRY,NODE,value,FILE,check=lambda *args:True)
                self.assertTrue(archive.close()['metadata_released']);self.assertEqual(archive.summary()['files'],0)

    def test_cid_and_file_reuse_across_declared_containers_refuse(self):
        for mode in ('cid','file'):
            with self.subTest(mode=mode):
                value=pod(uid=ENTRY['pod_uid']);value['status']={}
                value['spec']['containers'].append(dict(name='worker'))
                archive=PrivateCRIRuntimeArchive(history([value]),node_uid='node-uid',node_name='node-1',check=lambda *args:True,deadline=time.monotonic()+60)
                archive.capture(ENTRY,NODE,snapshots(),FILE,check=lambda *args:True)
                entry=dict(ENTRY,container_name='worker');snapshot=snapshots()
                for item in (snapshot['container'],snapshot['container_detail']['status']):
                    item['metadata']['name']='worker';item['labels']['io.kubernetes.container.name']='worker'
                    if mode=='file':item['id']='c'*64
                snapshot['container_detail']['status']['logPath']=snapshot['container_detail']['status']['logPath'].replace('/runtime/','/worker/')
                identity=dict(FILE,inode=2) if mode=='cid' else FILE
                with self.assertRaises(ValueError):archive.capture(entry,NODE,snapshot,identity,check=lambda *args:True)
                self.assertEqual(archive.summary()['files'],0);archive.close()

    def test_actual_file_cap_and_input_proof_copying(self):
        snapshot=snapshots();identity=dict(FILE)
        def mutate(proof,reserve):
            proof['immutable']['container_created']=0
            identity['inode']=9000;snapshot.clear()
            return True
        self.capture(snapshot=snapshot,file_identity=identity,check=mutate)
        self.assertEqual(self.resolve()['source'],SOURCE)
        self.assertIsNone(self.resolve(file_identity=identity))
        for inode in range(2,513):self.capture(file_identity=dict(FILE,inode=inode))
        self.assertEqual(self.archive.summary()['files'],512)
        with self.assertRaises(ValueError):self.capture(file_identity=dict(FILE,inode=513))
        self.assertEqual(self.archive.summary()['files'],0)

    def test_actual_entry_cap_refuses_additional_restart_without_mutating_history(self):
        self.capture()
        for index in range(1,129):
            entry=dict(ENTRY,restart_index=index);snapshot=snapshots()
            for item in (snapshot['container'],snapshot['container_detail']['status']):
                item['id']=format(index,'064x');item['metadata']['attempt']=index
            snapshot['container_detail']['status']['logPath']=snapshot['container_detail']['status']['logPath'].replace('/0.log','/'+str(index)+'.log')
            if index==128:
                self.assertEqual(self.archive.summary()['entries'],128)
                with self.assertRaises(ValueError):self.capture(entry=entry,snapshot=snapshot,file_identity=dict(FILE,inode=index+1))
            else:self.capture(entry=entry,snapshot=snapshot,file_identity=dict(FILE,inode=index+1))
        self.assertEqual(self.history.summary()['pending_containers'],1)
        self.assertEqual(self.archive.summary()['entries'],0)

    def test_sandbox_identity_cannot_be_reused_for_another_pod(self):
        other=dict(ENTRY,pod_name='other',pod_uid='11223344-5566-7788-9900-000000000001')
        first=pod(uid=ENTRY['pod_uid']);second=pod(name='other',uid=other['pod_uid'])
        first['status']=second['status']={}
        archive=PrivateCRIRuntimeArchive(history([first,second]),node_uid='node-uid',node_name='node-1',check=lambda *args:True,deadline=time.monotonic()+60)
        try:
            archive.capture(ENTRY,NODE,snapshots(),FILE,check=lambda *args:True)
            snapshot=snapshots()
            for item in (snapshot['container'],snapshot['container_detail']['status'],snapshot['sandbox'],snapshot['sandbox_detail']['status']):
                item['labels']['io.kubernetes.pod.uid']=other['pod_uid'];item['labels']['io.kubernetes.pod.name']='other'
            for item in (snapshot['container'],snapshot['container_detail']['status']):item['id']='c'*64
            for item in (snapshot['sandbox'],snapshot['sandbox_detail']['status']):
                item['metadata']['name']='other';item['metadata']['uid']=other['pod_uid']
            snapshot['container_detail']['status']['logPath']='/var/log/pods/'+BINDING['name']+'_other_'+other['pod_uid']+'/runtime/0.log'
            with self.assertRaises(ValueError):archive.capture(other,NODE,snapshot,dict(FILE,inode=2),check=lambda *args:True)
        finally:archive.close()

    def test_later_api_conflict_in_final_file_guard_is_refused(self):
        self.capture();calls=[]
        def guard(proof,reserve):
            calls.append(1)
            if len(calls)==2:
                start=self.history.begin();value=pod(uid=ENTRY['pod_uid'],current='containerd://'+'c'*64)
                self.history.accept(event(value));self.history.finish(receipt(start,1))
            return True
        with self.assertRaises(ValueError):self.resolve(check=guard)
        self.assertFalse(self.archive.summary()['valid'])

    def test_original_node_namespace_owner_and_guard_bounds_refuse(self):
        self.capture()
        with patch('evaluation.cri_archive.os.getpid',return_value=-1),self.assertRaises(ValueError):self.resolve()
        self.assertTrue(self.archive.summary()['valid'])
        self.allowed=False
        with self.assertRaises(ValueError):self.resolve()
        self.assertTrue(self.archive.summary()['metadata_released'])
        for mode in ('deadline','operations','file-check','node','namespace','history'):
            with self.subTest(mode=mode):
                archive=PrivateCRIRuntimeArchive(pending_history(),node_uid='node-uid',node_name='node-1',check=lambda *args:True,deadline=time.monotonic()+60)
                archive.capture(ENTRY,NODE,snapshots(),FILE,check=lambda *args:True)
                if mode=='deadline':archive._deadline=time.monotonic()+1
                if mode=='operations':archive._operations=4096
                if mode=='history':archive._history.abandon()
                args=dict(entry=ENTRY,file_identity=FILE,check=lambda *args:mode!='file-check')
                if mode=='node':args['file_identity']=dict(FILE,node_uid='other')
                if mode=='namespace':args['entry']=dict(ENTRY,namespace='foreign')
                with self.assertRaises(ValueError):archive.resolve(**args)
                self.assertEqual(archive.summary()['files'],0);archive.close()

    @unittest.skipUnless(sys.platform.startswith('linux'),'Linux held CRI descriptor required')
    def test_private_archive_can_bind_held_bytes_after_metadata_disappears(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'0.log';path.write_bytes(frame(b'private-archived-canary'))
            descriptor=os.open(path,os.O_RDONLY|os.O_CLOEXEC)
            retained=PrivateCRIRetention(BINDING);staging=PrivateCRIStaging(retained,check=lambda *args:True,deadline=time.monotonic()+60)
            try:
                identity=dict(node_uid='node-uid',device=os.fstat(descriptor).st_dev,inode=os.fstat(descriptor).st_ino)
                self.capture(file_identity=identity);staging.stage_descriptor(ENTRY,descriptor,node_uid='node-uid',check=lambda *args:True)
                path.unlink()
                self.assertFalse(retained.inspect(['private-archived-canary'])['canary_present'])
                projection=self.resolve(file_identity=identity)
                def check(proof,reserve):
                    resolved=self.resolve(file_identity=proof['files'][0])
                    return resolved['source']==proof['source'] and resolved['namespace_binding']==BINDING
                staging.bind(ENTRY,projection['source'],check=check)
                self.assertTrue(retained.inspect(['private-archived-canary'])['canary_present'])
                self.assertFalse(retained.inspect(['private-archived-canary'])['history_complete'])
            finally:
                staging.close();retained.close();os.close(descriptor)


if __name__=='__main__':unittest.main()
