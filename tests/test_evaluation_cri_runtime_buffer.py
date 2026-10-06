"""Unbound metadata stays private; missing births and lifecycle drift refuse."""
import time
import uuid
import unittest
from unittest.mock import patch

from evaluation.cri_runtime_buffer import PrivateCRIRuntimeEventBuffer
from evaluation.cri_archive import PrivateCRIRuntimeArchive
from test_evaluation_cri_binding import ENTRY, FILE, NODE, SOURCE, SECRET, pending_history
from test_evaluation_cri_runtime_event import runtime_event
from test_evaluation_pod_history import history, pod, event, receipt


class RuntimeBufferTest(unittest.TestCase):
    def setUp(self):
        self.history = pending_history(); self.allowed = True
        self.buffer = PrivateCRIRuntimeEventBuffer(self.history, node_uid='node-uid',
            node_name='node-1', check=lambda reserve:self.allowed, deadline=time.monotonic()+60)
        self.addCleanup(self.buffer.close)

    def lifecycle(self):
        for kind in ('CONTAINER_CREATED_EVENT','CONTAINER_STARTED_EVENT','CONTAINER_STOPPED_EVENT','CONTAINER_DELETED_EVENT'):
            value=runtime_event(kind)
            if kind=='CONTAINER_DELETED_EVENT': value['containersStatuses']=[]
            self.buffer.accept(value)

    def test_creation_survives_deletion_and_later_independent_file_admission(self):
        before=self.history.summary(); self.lifecycle()
        value=self.buffer.event_for(ENTRY)
        self.assertEqual(value['containerEventType'],'CONTAINER_CREATED_EVENT')
        self.assertEqual(self.history.summary(),before)
        self.assertEqual(self.buffer.summary()['deleted_entries'],1)
        archive=PrivateCRIRuntimeArchive(self.history,node_uid='node-uid',node_name='node-1',
            check=lambda reserve:True,deadline=time.monotonic()+60)
        self.addCleanup(archive.close)
        self.assertEqual(archive.capture_event(ENTRY,NODE,value,FILE,check=lambda *args:True)['source'],SOURCE)
        self.assertFalse(self.buffer.summary()['history_complete'])

    def test_raw_fields_and_mutable_aliases_are_not_retained(self):
        value=runtime_event();value['diagnostic']=SECRET
        value['containersStatuses'][0]['resources']={'private':SECRET}
        self.buffer.accept(value);value.clear()
        projected=self.buffer.event_for(ENTRY);projected.clear()
        self.assertEqual(self.buffer.event_for(ENTRY)['containerId'],SOURCE['container_id'].split('://')[1])
        self.assertNotIn(SECRET,repr(self.buffer._records))
        self.assertNotIn(ENTRY['pod_uid'],repr(self.buffer.summary()))

    def test_foreign_and_sandbox_events_cannot_create_records(self):
        value=runtime_event();value['podSandboxStatus']['metadata']['namespace']='foreign'
        self.buffer.accept(value)
        value=runtime_event();value['containerId']=value['podSandboxStatus']['id']
        self.buffer.accept(value)
        self.assertEqual(self.buffer.summary()['entries'],0)
        self.assertEqual(self.buffer.summary()['foreign_events'],1)
        self.assertEqual(self.buffer.summary()['sandbox_events'],1)

    def test_missing_birth_duplicate_and_skipped_state_permanently_refuse(self):
        for kinds in (['CONTAINER_STARTED_EVENT'],['CONTAINER_DELETED_EVENT'],
                      ['CONTAINER_CREATED_EVENT']*2,
                      ['CONTAINER_CREATED_EVENT','CONTAINER_STOPPED_EVENT']):
            b=PrivateCRIRuntimeEventBuffer(pending_history(),node_uid='node-uid',node_name='node-1',
                check=lambda reserve:True,deadline=time.monotonic()+60)
            try:
                with self.assertRaises(ValueError):
                    for kind in kinds:b.accept(runtime_event(kind))
                self.assertTrue(b.summary()['metadata_released'])
                with self.assertRaises(ValueError):b.event_for(ENTRY)
            finally:b.close()

    def test_immutable_container_and_tombstone_scope_drift_release_birth(self):
        for mode in ('time','path','labels','attempt','sandbox','tombstone'):
            b=PrivateCRIRuntimeEventBuffer(pending_history(),node_uid='node-uid',node_name='node-1',
                check=lambda reserve:True,deadline=time.monotonic()+60)
            try:
                b.accept(runtime_event());v=runtime_event('CONTAINER_STARTED_EVENT');s=v['containersStatuses'][0]
                if mode=='time':s['createdAt']='1700000000000000002'
                elif mode=='path':s['logPath']='/foreign'
                elif mode=='labels':s['labels']['io.kubernetes.pod.uid']='foreign'
                elif mode=='attempt':s['metadata']['attempt']=1
                elif mode=='sandbox':v['podSandboxStatus']['id']='c'*64
                else:
                    b.accept(v);b.accept(runtime_event('CONTAINER_STOPPED_EVENT'))
                    v=runtime_event('CONTAINER_DELETED_EVENT');v['podSandboxStatus']['id']='c'*64
                with self.assertRaises(ValueError):b.accept(v)
                self.assertEqual(b.summary()['entries'],0)
            finally:b.close()

    def test_original_guard_deadline_and_history_failure_release_metadata(self):
        self.buffer.accept(runtime_event());self.allowed=False
        with self.assertRaises(ValueError):self.buffer.event_for(ENTRY)
        self.assertTrue(self.buffer.summary()['metadata_released'])
        for mode in ('deadline','history'):
            h=pending_history();b=PrivateCRIRuntimeEventBuffer(h,node_uid='node-uid',node_name='node-1',
                check=lambda reserve:True,deadline=time.monotonic()+60)
            try:
                b.accept(runtime_event())
                if mode=='deadline':b._deadline=time.monotonic()+1
                else:h.abandon()
                with self.assertRaises(ValueError):b.event_for(ENTRY)
                self.assertTrue(b.summary()['metadata_released'])
            finally:b.close()

    def test_unknown_api_declaration_never_assigns_identity(self):
        self.buffer.accept(runtime_event())
        self.assertIsNone(self.buffer.event_for(dict(ENTRY,container_name='unknown')))
        self.assertTrue(self.buffer.summary()['valid'])

    def test_event_waits_for_later_original_watch_declaration(self):
        h=history([])
        b=PrivateCRIRuntimeEventBuffer(h,node_uid='node-uid',node_name='node-1',
            check=lambda reserve:True,deadline=time.monotonic()+60)
        self.addCleanup(b.close)
        b.accept(runtime_event())
        self.assertIsNone(b.event_for(ENTRY))
        start=h.begin();value=pod(uid=ENTRY['pod_uid']);value['status']={}
        h.accept(event(value,'ADDED'));h.finish(receipt(start,1))
        self.assertEqual(b.event_for(ENTRY)['containerId'],SOURCE['container_id'].split('://')[1])
        self.assertEqual(h.sources(),[])

    def test_known_api_conflict_and_foreign_node_declaration_refuse(self):
        for mode in ('cid','node'):
            value=pod(uid=ENTRY['pod_uid'],current='containerd://'+'c'*64)
            if mode=='node':value['status']={};value['spec']['nodeName']='foreign-node'
            b=PrivateCRIRuntimeEventBuffer(history([value]),node_uid='node-uid',node_name='node-1',
                check=lambda reserve:True,deadline=time.monotonic()+60)
            try:
                b.accept(runtime_event())
                with self.assertRaises(ValueError):b.event_for(ENTRY)
                self.assertTrue(b.summary()['metadata_released'])
            finally:b.close()

    def test_bounds_refuse_without_publishing_private_values(self):
        self.buffer.accept(runtime_event())
        with patch('evaluation.cri_runtime_buffer.MAX_OPERATIONS',self.buffer.summary()['operations']):
            with self.assertRaisesRegex(ValueError,'^Private runtime buffer unavailable$'):self.buffer.event_for(ENTRY)
        self.assertEqual(self.buffer.summary()['entries'],0)
        b=PrivateCRIRuntimeEventBuffer(pending_history(),node_uid='node-uid',node_name='node-1',
            check=lambda reserve:True,deadline=time.monotonic()+60)
        try:
            with patch('evaluation.cri_runtime_buffer.MAX_ENTRIES',0):
                with self.assertRaises(ValueError):b.accept(runtime_event())
            self.assertTrue(b.summary()['metadata_released'])
        finally:b.close()

    def test_bad_scope_timestamp_and_state_are_not_coerced(self):
        for mode in ('uid','timestamp','state','attempt'):
            b=PrivateCRIRuntimeEventBuffer(pending_history(),node_uid='node-uid',node_name='node-1',
                check=lambda reserve:True,deadline=time.monotonic()+60)
            try:
                v=runtime_event()
                if mode=='uid':v['podSandboxStatus']['metadata']['uid']=SECRET
                elif mode=='timestamp':v['createdAt']=True
                elif mode=='state':v['podSandboxStatus']['state']=SECRET
                else:v['podSandboxStatus']['metadata']['attempt']=True
                with self.assertRaises(ValueError) as failure:b.accept(v)
                self.assertNotIn(SECRET,str(failure.exception))
                self.assertNotIn(SECRET,repr(b._records))
            finally:b.close()

    def test_actual_entry_and_operation_capacity_boundaries(self):
        for i in range(128):
            v=runtime_event();sid=format(1000+i,'064x');cid=format(2000+i,'064x')
            uid=str(uuid.UUID(int=i+1));name='api-'+str(i)
            v['containerId']=cid;v['podSandboxStatus']['id']=sid
            v['podSandboxStatus']['metadata'].update(uid=uid,name=name)
            for labels in (v['podSandboxStatus']['labels'],v['containersStatuses'][0]['labels']):
                labels.update({'io.kubernetes.pod.uid':uid,'io.kubernetes.pod.name':name})
            v['containersStatuses'][0]['id']=cid
            v['containersStatuses'][0]['logPath']='/var/log/pods/'+ENTRY['namespace']+'_'+name+'_'+uid+'/runtime/0.log'
            self.buffer.accept(v)
        self.assertEqual(self.buffer.summary()['entries'],128)
        with self.assertRaises(ValueError):self.buffer.accept(runtime_event())
        self.assertTrue(self.buffer.summary()['metadata_released'])
        b=PrivateCRIRuntimeEventBuffer(pending_history(),node_uid='node-uid',node_name='node-1',
            check=lambda reserve:True,deadline=time.monotonic()+60)
        try:
            value=runtime_event();value['podSandboxStatus']['metadata']['namespace']='foreign'
            for _ in range(4096):b.accept(value)
            self.assertEqual(b.summary()['operations'],4096)
            with self.assertRaises(ValueError):b.accept(value)
            self.assertTrue(b.summary()['metadata_released'])
        finally:b.close()
