"""Runtime metadata cannot fabricate or contradict anchored file attribution."""
import copy
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from evaluation.cri_binding import bind_cri_log_source
from evaluation.cri_staging import PrivateCRIStaging
from evaluation.log_retention import PrivateCRIRetention
from test_evaluation_pod_history import BINDING, history, pod, event, receipt
from test_evaluation_cri_follower import frame


UID='11223344-5566-7788-9900-aabbccddeeff'
CID='a'*64;SID='b'*64
ENTRY=dict(namespace=BINDING['name'],pod_name='api',pod_uid=UID,container_name='runtime',restart_index=0)
SOURCE={key:ENTRY[key] for key in ENTRY if key!='restart_index'} | dict(container_id='containerd://'+CID,previous=False)
NODE=dict(apiVersion='v1',kind='Node',metadata=dict(name='node-1',uid='node-uid'),status=dict(nodeInfo=dict(containerRuntimeVersion='containerd://2.1.5-k3s1')))
FILE=dict(node_uid='node-uid',device=1,inode=1)
SECRET='private-OCI-environment-must-not-appear'


def snapshots():
    labels={'io.kubernetes.pod.uid':UID,'io.kubernetes.pod.name':'api','io.kubernetes.pod.namespace':BINDING['name']}
    container=dict(id=CID,podSandboxId=SID,metadata=dict(name='runtime',attempt=0),state='CONTAINER_RUNNING',createdAt='1700000000000000001',labels=dict(labels,**{'io.kubernetes.container.name':'runtime'}),annotations={'private':SECRET})
    sandbox=dict(id=SID,metadata=dict(name='api',uid=UID,namespace=BINDING['name'],attempt=0),state='SANDBOX_READY',createdAt='1700000000000000000',labels=labels,annotations={'private':SECRET})
    status=copy.deepcopy(container);status.pop('podSandboxId');status['logPath']='/var/log/pods/'+BINDING['name']+'_api_'+UID+'/runtime/0.log'
    return dict(container=container,container_detail=dict(status=status,info=dict(sandboxID=SID,runtimeSpec={'process':{'env':[SECRET]}},config={'private':SECRET})),sandbox=sandbox,sandbox_detail=dict(status=copy.deepcopy(sandbox),info={'private':SECRET}))


def pending_history():
    value=pod(uid=UID);value['status']={};return history([value])


class CRIBindingTest(unittest.TestCase):
    def test_absent_api_cid_is_independently_projected_without_mutating_history(self):
        h=pending_history();result=bind_cri_log_source(h,ENTRY,NODE,snapshots(),FILE)
        self.assertEqual(result['source'],SOURCE);self.assertEqual(result['role'],'containers')
        self.assertEqual(result['namespace_binding'],BINDING)
        self.assertTrue(result['api_pending']);self.assertFalse(result['api_container_id_observed'])
        self.assertFalse(result['history_complete']);self.assertNotIn(SECRET,repr(result))
        self.assertEqual(h.sources(),[]);self.assertEqual(h.summary()['pending_containers'],1)
        self.assertFalse(h.summary()['history_complete'])

    def test_regular_init_and_ephemeral_declarations_preserve_role(self):
        for role in ('containers','initContainers','ephemeralContainers'):
            value=pod(uid=UID,role=role);value['status']={};h=history([value])
            name='runtime' if role=='containers' else 'additional';entry=dict(ENTRY,container_name=name)
            s=snapshots()
            for observed in (s['container'],s['container_detail']['status']):
                observed['metadata']['name']=name;observed['labels']['io.kubernetes.container.name']=name
            s['container_detail']['status']['logPath']=s['container_detail']['status']['logPath'].replace('/runtime/','/'+name+'/')
            self.assertEqual(bind_cri_log_source(h,entry,NODE,s,FILE)['role'],role)

    def test_known_api_identity_matches_or_refuses_conflict_and_cross_index_reuse(self):
        h=history([pod(uid=UID,current=SOURCE['container_id'])])
        self.assertTrue(bind_cri_log_source(h,ENTRY,NODE,snapshots(),FILE)['api_container_id_observed'])
        for h in (history([pod(uid=UID,current='containerd://'+'c'*64)]),
                  history([pod(uid=UID,count=1,current='containerd://'+'d'*64,prior=SOURCE['container_id'])])):
            entry=ENTRY;s=snapshots()
            if h.summary()['identities']==2:
                entry=dict(ENTRY,restart_index=1)
                for value in (s['container'],s['container_detail']['status']):value['metadata']['attempt']=1
                s['container_detail']['status']['logPath']=s['container_detail']['status']['logPath'].replace('/0.log','/1.log')
            with self.assertRaises(ValueError):bind_cri_log_source(h,entry,NODE,s,FILE)

    def test_unknown_declarations_unscheduled_nodes_and_deleted_pending_are_explicit(self):
        h=pending_history()
        for field in ('namespace','pod_name','pod_uid','container_name'):
            self.assertIsNone(bind_cri_log_source(h,dict(ENTRY,**{field:'unknown'}),NODE,snapshots(),FILE))
        value=pod(uid=UID);value['status']={};value['spec'].pop('nodeName')
        with self.assertRaises(ValueError):bind_cri_log_source(history([value]),ENTRY,NODE,snapshots(),FILE)
        start=h.begin();value=pod(uid=UID);value['status']={}
        h.accept(event(value,'DELETED'));h.finish(receipt(start,1))
        s=snapshots();s['container']['state']=s['container_detail']['status']['state']='CONTAINER_EXITED'
        s['sandbox']['state']=s['sandbox_detail']['status']['state']='SANDBOX_NOTREADY'
        self.assertTrue(bind_cri_log_source(h,ENTRY,NODE,s,FILE)['pod_deleted'])
        self.assertEqual(h.summary()['unresolved_deleted_containers'],1)

    def test_every_container_sandbox_scope_and_link_mismatch_refuses(self):
        for target in ('container','container_status','sandbox','sandbox_status'):
            for label in ('io.kubernetes.pod.uid','io.kubernetes.pod.name','io.kubernetes.pod.namespace'):
                with self.subTest(target=target,label=label):
                    s=snapshots();value=s['container_detail']['status'] if target=='container_status' else s['sandbox_detail']['status'] if target=='sandbox_status' else s[target]
                    value['labels'][label]='foreign'
                    with self.assertRaisesRegex(ValueError,'^Private CRI log binding unavailable$'):bind_cri_log_source(pending_history(),ENTRY,NODE,s,FILE)
        for field,target in (('id','container'),('podSandboxId','container'),('id','sandbox')):
            s=snapshots();s[target][field]='c'*64
            with self.assertRaises(ValueError):bind_cri_log_source(pending_history(),ENTRY,NODE,s,FILE)
        for target,field in ((('container_detail','info'),'sandboxID'),(('container_detail','status'),'id'),(('sandbox_detail','status'),'id')):
            s=snapshots();s[target[0]][target[1]][field]='c'*64
            with self.assertRaises(ValueError):bind_cri_log_source(pending_history(),ENTRY,NODE,s,FILE)
        s=snapshots();s['container']['id']=s['container_detail']['status']['id']='a'*12
        with self.assertRaises(ValueError):bind_cri_log_source(pending_history(),ENTRY,NODE,s,FILE)

    def test_attempt_metadata_states_paths_and_creation_times_are_not_coerced(self):
        for mode in ('attempt-bool','attempt-string','attempt-negative','attempt-index','container-name','sandbox-uid','sandbox-attempt','state','sandbox-state','path','time-string','time-order','time-mismatch','time-overflow'):
            with self.subTest(mode=mode):
                s=snapshots();c=s['container'];status=s['container_detail']['status'];sandbox=s['sandbox'];ss=s['sandbox_detail']['status']
                if mode.startswith('attempt-'):
                    v={'attempt-bool':False,'attempt-string':'0','attempt-negative':-1,'attempt-index':1}[mode]
                    c['metadata']['attempt']=status['metadata']['attempt']=v
                elif mode=='container-name':c['metadata']['name']=status['metadata']['name']='other'
                elif mode=='sandbox-uid':sandbox['metadata']['uid']=ss['metadata']['uid']='other'
                elif mode=='sandbox-attempt':sandbox['metadata']['attempt']=ss['metadata']['attempt']=True
                elif mode=='state':c['state']='CONTAINER_UNKNOWN'
                elif mode=='sandbox-state':ss['state']='UNKNOWN'
                elif mode=='path':status['logPath']='/var/log/pods/foreign/0.log'
                elif mode=='time-string':c['createdAt']=status['createdAt']=1700000000000000001
                elif mode=='time-order':sandbox['createdAt']=ss['createdAt']='1700000000000000002'
                elif mode=='time-mismatch':status['createdAt']='1700000000000000002'
                elif mode=='time-overflow':c['createdAt']=status['createdAt']=str(2**63)
                with self.assertRaises(ValueError):bind_cri_log_source(pending_history(),ENTRY,NODE,s,FILE)

    def test_refusals_report_fixed_reasons_without_raw_runtime_diagnostics(self):
        for mode,reason in (('labels','scope_labels'),('path','log_path'),('shape','shape'),('history','input_or_history')):
            h=pending_history();s=snapshots()
            if mode=='labels':s['container']['labels']['io.kubernetes.pod.uid']=SECRET
            if mode=='path':s['container_detail']['status']['logPath']=SECRET
            if mode=='shape':s['container_detail']['status']=SECRET
            if mode=='history':h.abandon()
            with self.assertRaises(ValueError) as raised:bind_cri_log_source(h,ENTRY,NODE,s,FILE)
            self.assertEqual(raised.exception.reason,reason)
            self.assertEqual(str(raised.exception),'Private CRI log binding unavailable')
            self.assertNotIn(SECRET,repr(raised.exception.__dict__))

    def test_node_file_bounds_history_ownership_and_private_copies(self):
        for mode in ('node-name','node-uid','node-kind','node-deleted','runtime','file','bounds','history','owner'):
            with self.subTest(mode=mode):
                n=copy.deepcopy(NODE);f=dict(FILE);s=snapshots();h=pending_history()
                if mode=='node-name':n['metadata']['name']='other'
                if mode=='node-uid':n['metadata']['uid']='other'
                if mode=='node-kind':n['kind']='Pod'
                if mode=='node-deleted':n['metadata']['deletionTimestamp']='deleted'
                if mode=='runtime':n['status']['nodeInfo']['containerRuntimeVersion']='docker://version'
                if mode=='file':f['inode']=False
                if mode=='bounds':s['container_detail']['info']['private']='x'*(2*1024*1024)
                if mode=='history':h.abandon()
                context=patch('evaluation.pod_history.os.getpid',return_value=-1) if mode=='owner' else patch('evaluation.cri_binding.MAX_INPUT_BYTES',2*1024*1024)
                with context,self.assertRaisesRegex(ValueError,'^Private CRI log binding unavailable$'):bind_cri_log_source(h,ENTRY,n,s,f)
        result=bind_cri_log_source(pending_history(),ENTRY,NODE,snapshots(),FILE)
        result['file_identity']['inode']=2;result['source']['container_id']='tampered'
        fresh=bind_cri_log_source(pending_history(),ENTRY,NODE,snapshots(),FILE)
        self.assertEqual(fresh['file_identity'],FILE);self.assertEqual(fresh['source'],SOURCE)

    @unittest.skipUnless(sys.platform.startswith('linux'),'Actual Linux staging integration')
    def test_runtime_projection_attributes_existing_private_bytes_without_api_cid(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'0.log';path.write_bytes(frame(b'private-early-runtime-canary'))
            st=path.stat();file_id=dict(node_uid='node-uid',device=st.st_dev,inode=st.st_ino)
            r=PrivateCRIRetention(BINDING);m=PrivateCRIStaging(r,check=lambda reserve:True,deadline=time.monotonic()+90)
            h=pending_history()
            try:
                m.stage(ENTRY,directory,node_uid='node-uid',check=lambda *args:True)
                self.assertFalse(r.inspect(['private-early-runtime-canary'])['canary_present'])
                binding=bind_cri_log_source(h,ENTRY,NODE,snapshots(),file_id)
                def verify(proof,reserve):
                    observed=bind_cri_log_source(h,proof['entry'],NODE,snapshots(),file_id)
                    return observed['namespace_binding']==r._binding and observed['source']==proof['source'] and proof['files']==[observed['file_identity']]
                m.bind(ENTRY,binding['source'],check=verify)
                self.assertTrue(r.inspect(['private-early-runtime-canary'])['canary_present'])
                self.assertEqual(h.sources(),[]);self.assertEqual(h.summary()['pending_containers'],1)
                self.assertTrue(m.close()['descriptors_closed'])
            finally:m.close();r.close()
