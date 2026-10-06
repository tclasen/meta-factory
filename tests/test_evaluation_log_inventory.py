"""Available source inventory never substitutes for continuous history proof."""
import copy
import unittest

from evaluation.log_inventory import available_log_inventory


BINDING = dict(name='incident-app', uid='namespace-uid')
NAMESPACE = dict(apiVersion='v1', kind='Namespace', metadata=dict(name='incident-app', uid='namespace-uid'))


def fixture():
    pod = dict(metadata=dict(name='api', namespace='incident-app', uid='pod-uid'),
               spec=dict(containers=[dict(name='api')]), status=dict(containerStatuses=[
                   dict(name='api', restartCount=0, containerID='containerd://one', state={'running': {}}, lastState={})]))
    return dict(apiVersion='v1', kind='PodList', metadata=dict(resourceVersion='100'), items=[pod])


class LogInventoryTest(unittest.TestCase):
    def inspect(self, pods, namespace=NAMESPACE):
        return available_log_inventory(namespace, pods, binding=BINDING)

    def test_current_previous_init_sidecar_and_ephemeral_sources(self):
        pods=fixture(); pod=pods['items'][0]
        for declarations, statuses, name, state in [('initContainers','initContainerStatuses','init','terminated'),
                                                    ('ephemeralContainers','ephemeralContainerStatuses','debug','running')]:
            pod['spec'][declarations]=[dict(name=name)]
            pod['status'][statuses]=[dict(name=name,restartCount=0,containerID='containerd://'+name,state={state:{}},lastState={})]
        pod['spec']['initContainers'].append(dict(name='sidecar',restartPolicy='Always'))
        pod['status']['initContainerStatuses'].append(dict(name='sidecar',restartCount=1,containerID='containerd://new',state={'running':{}},lastState={'terminated':{'containerID':'containerd://old'}}))
        result=self.inspect(pods)
        self.assertEqual(len(result['sources']),5)
        self.assertEqual({v['container_name'] for v in result['sources']},{'api','init','debug','sidecar'})
        self.assertFalse(result['restart_history_gap'])
        self.assertEqual([v['container_id'] for v in result['sources'] if v['previous']],['containerd://old'])

    def test_restart_history_gap_is_explicit_and_changes_fingerprint(self):
        pods=fixture(); status=pods['items'][0]['status']['containerStatuses'][0]
        initial=self.inspect(pods)
        status.update(restartCount=1,lastState={'terminated':{'containerID':'containerd://prior'}})
        once=self.inspect(pods)
        status['restartCount']=2
        twice=self.inspect(pods)
        self.assertFalse(once['restart_history_gap']);self.assertTrue(twice['restart_history_gap'])
        self.assertNotEqual(initial['fingerprint'],once['fingerprint'])
        self.assertNotEqual(once['fingerprint'],twice['fingerprint'])

    def test_complete_list_and_namespace_identity_required(self):
        for change in (lambda p:p['metadata'].update(continue_='ignored',**{'continue':'next'}),
                       lambda p:p['metadata'].update(remainingItemCount=1),
                       lambda p:p['metadata'].update(remainingItemCount=False),
                       lambda p:p['metadata'].pop('resourceVersion'),
                       lambda p:p['items'][0]['metadata'].update(namespace='other'),
                       lambda p:p['items'].append(copy.deepcopy(p['items'][0]))):
            pods=fixture();change(pods)
            with self.assertRaises(ValueError):self.inspect(pods)
        for field,value in [('uid','replacement'),('name','other'),('deletionTimestamp','now')]:
            namespace=copy.deepcopy(NAMESPACE);namespace['metadata'][field]=value
            with self.assertRaises(ValueError):self.inspect(fixture(),namespace)

    def test_missing_duplicate_or_ambiguous_container_status_refused(self):
        mutations=[lambda p:p['status'].update(containerStatuses=[]),
                   lambda p:p['status']['containerStatuses'][0].update(containerID=''),
                   lambda p:p['status']['containerStatuses'][0].update(restartCount=True),
                   lambda p:p['status']['containerStatuses'][0].update(restartCount=1),
                   lambda p:p['status']['containerStatuses'][0].update(state={'running':{},'terminated':{}}),
                   lambda p:p['status']['containerStatuses'][0].update(lastState={'terminated':{}}),
                   lambda p:p['spec'].update(initContainers=[dict(name='api')])]
        for mutate in mutations:
            pods=fixture();mutate(pods['items'][0])
            with self.assertRaises(ValueError):self.inspect(pods)

    def test_never_started_waiting_has_no_source_but_restarted_waiting_is_unavailable(self):
        pods=fixture(); status=pods['items'][0]['status']['containerStatuses'][0]
        status.update(state={'waiting':{}},containerID='')
        self.assertEqual(self.inspect(pods)['sources'],[])
        status['restartCount']=1
        with self.assertRaises(ValueError):self.inspect(pods)

    def test_fingerprint_stable_across_resource_version_order_and_irrelevant_secret_fields(self):
        pods=fixture()
        second=copy.deepcopy(pods['items'][0]);second['metadata'].update(name='worker',uid='pod-uid-2')
        second['status']['containerStatuses'][0]['containerID']='containerd://worker'
        pods['items'].append(second)
        initial=self.inspect(pods);pods['items'].reverse()
        pods['metadata']['resourceVersion']='101'
        pods['items'][0]['metadata']['annotations']={'private':'secret-value'}
        changed=self.inspect(pods)
        self.assertEqual(initial['fingerprint'],changed['fingerprint'])
        self.assertNotIn('secret-value',repr(changed))
        pods['items'][0]['status']['containerStatuses'][0]['containerID']='containerd://replacement'
        self.assertNotEqual(initial['fingerprint'],self.inspect(pods)['fingerprint'])


if __name__=='__main__':unittest.main()
