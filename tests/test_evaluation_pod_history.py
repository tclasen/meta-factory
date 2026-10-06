"""Anchored identity history cannot silently forget deleted/restarted sources."""
import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from evaluation.pod_history import PodIdentityHistory


BINDING = dict(name='incident-app', uid='namespace-uid')
NAMESPACE = dict(apiVersion='v1',kind='Namespace',metadata=dict(BINDING))
SECRET = 'Private-Pod-metadata-secret'


def pod(name='api',uid='pod-one',count=0,current='containerd://one',prior=None,state='running',role='containers'):
    status_key = {'containers':'containerStatuses','initContainers':'initContainerStatuses','ephemeralContainers':'ephemeralContainerStatuses'}[role]
    declarations = {'containers':[dict(name='runtime')]}
    if role!='containers':declarations[role]=[dict(name='additional')]
    container = 'runtime' if role=='containers' else 'additional'
    observation = dict(name=container,restartCount=count,containerID=current,state={state:{}},lastState={'terminated':dict(containerID=prior)} if prior else {})
    return dict(apiVersion='v1',kind='Pod',metadata=dict(name=name,namespace=BINDING['name'],uid=uid,resourceVersion='pod-version',annotations={'secret':SECRET}),
                spec=dict(nodeName='node-1',**declarations),status={status_key:[observation]})


def history(items=()):
    return PodIdentityHistory(NAMESPACE,dict(apiVersion='v1',kind='PodList',metadata=dict(resourceVersion='opaque-anchor'),items=list(items)),binding=BINDING)


def event(value,kind='MODIFIED'):
    return dict(type=kind,object=value)


def receipt(start,count,**changes):
    result=dict(outcome='watch_window_closed',window_id=start['window_id'],events=count,
                binding_sha256=hashlib.sha256(json.dumps(BINDING,sort_keys=True).encode()).hexdigest(),
                anchor_sha256=hashlib.sha256(start['resource_version'].encode()).hexdigest(),
                source_verified_before=True,source_verified_after=True,client_group_absent=True)
    result.update(changes);return result


class PodHistoryTest(unittest.TestCase):
    def test_typed_podlist_supplies_omitted_item_typemeta_but_never_overrides_wrong_type(self):
        value=pod();value.pop('apiVersion');value.pop('kind')
        h=history([value]);self.assertEqual(h.summary()['identities'],1)
        with self.assertRaises(ValueError):history([dict(value,kind='Secret')])
        with self.assertRaises(ValueError):history([dict(value,apiVersion='apps/v1')])
        h.begin()
        with self.assertRaises(ValueError):h.accept(event(value))

    def test_pending_add_start_delete_and_same_name_recreation_retain_both_uids(self):
        h=history();start=h.begin();pending=pod();pending['status']={};pending['spec'].pop('nodeName')
        h.accept(event(pending,'ADDED'))
        self.assertEqual(h.summary()['pending_containers'],1);self.assertEqual(h.sources(),[])
        running=pod();h.accept(event(running));h.accept(event(running,'DELETED'))
        h.accept(event(pod(uid='pod-two',current='containerd://two'),'ADDED'))
        summary=h.finish(receipt(start,4))
        self.assertEqual((summary['pods_seen'],summary['deleted_pods'],summary['active_pods'],summary['identities']),(2,1,1,2))
        sources=h.sources();self.assertEqual([s['available_as'] for s in sources],['historical','current'])
        self.assertNotIn(SECRET,repr(h._pods));self.assertNotIn('pod-one',repr(summary));self.assertFalse(summary['history_complete'])

    def test_deleted_pending_declarations_remain_explicit_across_same_name_recreation(self):
        value=pod();value['status']={}
        h=history([value]);start=h.begin();h.accept(event(value,'DELETED'))
        h.accept(event(pod(uid='new-pod',current='containerd://new'),'ADDED'))
        summary=h.finish(receipt(start,2))
        self.assertEqual(summary['pending_containers'],0)
        self.assertEqual(summary['unresolved_deleted_containers'],1)
        self.assertEqual(summary['identities'],1)
        self.assertFalse(summary['history_complete'])

    def test_waiting_after_restart_does_not_alias_cached_current_id_as_new_instance(self):
        h=history([pod()]);start=h.begin()
        h.accept(event(pod(count=1,current='containerd://one',prior='containerd://one',state='waiting')))
        self.assertEqual(h.summary()['pending_containers'],1);self.assertEqual(len(h.sources()),1)
        h.accept(event(pod(count=1,current='containerd://two',prior='containerd://one')))
        h.accept(event(pod(count=2,current='containerd://three',prior='containerd://two')))
        h.finish(receipt(start,3))
        self.assertEqual([s['restart_index'] for s in h.sources()],[0,1,2])
        self.assertEqual([s['available_as'] for s in h.sources()],['historical','previous','current'])
        self.assertFalse(h.summary()['identity_gap'])

    def test_skipped_unknown_identities_stay_incomplete_and_missing_status_is_pending(self):
        h=history([pod(count=3,current='containerd://four',prior='containerd://three')])
        self.assertTrue(h.summary()['identity_gap']);start=h.begin()
        value=pod(count=3,current='containerd://four',prior='containerd://three');value['status']={}
        h.accept(event(value));h.finish(receipt(start,1))
        self.assertEqual(len(h.sources()),2);self.assertEqual(h.summary()['pending_containers'],1)
        self.assertTrue(h.summary()['identity_gap'])

    def test_all_container_roles_and_ephemeral_additions_are_private_collector_inputs(self):
        initial=pod();h=history([initial]);start=h.begin()
        value=pod(role='ephemeralContainers',current='containerd://ephemeral')
        value['status']['containerStatuses']=initial['status']['containerStatuses']
        h.accept(event(value));h.finish(receipt(start,1))
        self.assertEqual({s['role'] for s in h.sources()},{'containers','ephemeralContainers'})
        init=pod(role='initContainers',current='containerd://init')
        init['status']['containerStatuses']=initial['status']['containerStatuses']
        self.assertEqual({s['role'] for s in history([init]).sources()},{'containers','initContainers'})
        terminated=pod(state='terminated',current=None);terminated['status']['containerStatuses'][0]['state']['terminated']['containerID']='containerd://terminated'
        self.assertEqual(history([terminated]).sources()[0]['source']['container_id'],'containerd://terminated')

    def test_unknown_replayed_conflicting_regressed_and_mutated_identity_events_refuse(self):
        for condition in ('unknown','duplicate','resurrect','count','index','reuse','node','declaration','namespace','zero'):
            h=history([pod()]);h.begin();value=pod()
            with self.subTest(condition=condition),self.assertRaisesRegex(ValueError,'^Private Pod identity history unavailable$'):
                if condition=='unknown':value['metadata']['uid']='other';h.accept(event(value,'DELETED'))
                elif condition=='duplicate':h.accept(event(value,'ADDED'))
                elif condition=='resurrect':h.accept(event(value,'DELETED'));h.accept(event(value,'ADDED'))
                elif condition=='count':h.accept(event(pod(count=1,current='containerd://two',prior='containerd://one')));h.accept(event(value))
                elif condition=='index':h.accept(event(pod(current='containerd://other')))
                elif condition=='reuse':h.accept(event(pod(count=1,current='containerd://one',prior='containerd://one')))
                elif condition=='node':value['spec']['nodeName']='node-2';h.accept(event(value))
                elif condition=='declaration':value['spec']['containers']=[dict(name='renamed')];value['status']={};h.accept(event(value))
                elif condition=='namespace':value['metadata']['namespace']='other';h.accept(event(value))
                else:value['metadata']['resourceVersion']='0';h.accept(event(value))
            self.assertFalse(h.summary()['valid'])
            with self.assertRaises(ValueError):h.begin()
            with self.assertRaises(ValueError):h.sources()

    def test_exact_window_receipt_failure_and_abandonment_permanently_invalidate(self):
        for failure in ('outcome','count','foreign','abandon'):
            h=history();start=h.begin();h.accept(event(pod(),'ADDED'))
            if failure=='abandon':h.abandon()
            else:
                changes={'outcome':'incomplete'} if failure=='outcome' else {'events':0} if failure=='count' else {'window_id':'other'}
                with self.assertRaises(ValueError):h.finish(receipt(start,1,**changes))
            self.assertFalse(h.summary()['valid']);self.assertEqual(h.summary()['pods_seen'],1)
            with self.assertRaises(ValueError):h.begin()

    def test_complete_snapshot_validation_bounds_parent_and_copied_private_sources(self):
        for change in ('namespace','pagination','zero','duplicate','listkind'):
            namespace=copy.deepcopy(NAMESPACE);pods=dict(apiVersion='v1',kind='PodList',metadata=dict(resourceVersion='anchor'),items=[pod()])
            if change=='namespace':namespace['metadata']['uid']='wrong'
            elif change=='pagination':pods['metadata']['continue']='private-token'
            elif change=='zero':pods['metadata']['resourceVersion']='0'
            elif change=='duplicate':pods['items'].append(pod())
            else:pods['kind']='List'
            with self.assertRaises(ValueError):PodIdentityHistory(namespace,pods,binding=BINDING)
        for bound in ('MAX_PODS','MAX_CONTAINERS','MAX_IDENTITIES','MAX_SNAPSHOT_BYTES'):
            with patch('evaluation.pod_history.'+bound,0),self.assertRaises(ValueError):history([pod()])
        original=pod();h=history([original]);original['status']['containerStatuses'][0]['containerID']='changed'
        values=h.sources();values[0]['source']['container_id']='changed'
        self.assertEqual(h.sources()[0]['source']['container_id'],'containerd://one')
        with patch('evaluation.pod_history.os.getpid',return_value=-1),self.assertRaises(ValueError):h.begin()
        h.begin()


if __name__=='__main__':unittest.main()
