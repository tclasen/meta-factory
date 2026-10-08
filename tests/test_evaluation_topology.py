"""Live-resource projections and actual bounded subprocess sanitization."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

from evaluation.evidence import Attempt
from evaluation.topology import capture_topology
from evaluation.topology_probe import project, scope
from evaluation.verdicts import Inconclusive


PIN = 'example/fixture@sha256:' + 'a'*64
RUNTIME = 'containerd://sha256:' + 'b'*64


def fixtures(kinds=None):
    kinds = kinds or {}
    selected = dict(components={}, services={})
    objects = []
    def meta(name):
        return dict(name=name,namespace='incident-app',uid=str(uuid.uuid4()),generation=1,
                    labels={'do-not-log':'secret-label-canary'})
    for index, role in enumerate(('web','api','worker','database','storage')):
        kind = kinds.get(role,'Deployment')
        workload = dict(kind=kind,metadata=meta(role),spec={'replicas':1},
                        status={'observedGeneration':1,'desiredNumberScheduled':1})
        pod = dict(kind='Pod',metadata=meta(role+'-pod'),
                   spec={'containers':[dict(name='main',image=PIN,env=[dict(name='SECRET',value='secret-env-canary')])]},
                   status=dict(phase='Running',podIP='10.42.0.'+str(index+2),
                               conditions=[dict(type='Ready',status='True')],
                               containerStatuses=[dict(name='main',imageID=RUNTIME,ready=True,state={'running':{}})]))
        if kind == 'Pod':
            workload = pod;workload['metadata']['name']=role
        else:
            parent = workload
            if kind == 'Deployment':
                parent = dict(kind='ReplicaSet',metadata=meta(role+'-rs'),spec={},status={})
                parent['metadata']['ownerReferences']=[dict(kind=kind,uid=workload['metadata']['uid'],controller=True)]
                objects.append(parent)
            pod['metadata']['ownerReferences']=[dict(kind=parent['kind'],uid=parent['metadata']['uid'],controller=True)]
            objects.append(pod)
        objects.append(workload)
        selected['components'][role]=dict(kind=kind,name=role,container='main')
        if role != 'worker':
            selected['services'][role]=role
            service = dict(kind='Service',metadata=meta(role),spec=dict(type='ClusterIP',clusterIP='10.43.0.'+str(index+2),ports=[dict(port=8080)]))
            endpoint = dict(kind='EndpointSlice',metadata=meta(role+'-endpoints'),
                            endpoints=[dict(conditions={'ready':True},addresses=[pod['status']['podIP']],
                                            targetRef=dict(kind='Pod',namespace='incident-app',name=pod['metadata']['name'],uid=pod['metadata']['uid']))])
            endpoint['metadata']['labels']['kubernetes.io/service-name']=role
            endpoint['metadata']['ownerReferences']=[dict(kind='Service',uid=service['metadata']['uid'],controller=True)]
            objects.extend([service,endpoint])
    namespaces = {'items':[dict(kind='Namespace',metadata=dict(name=name,uid=str(uuid.uuid4())))
                           for name in ('kube-system','incident-app')]}
    return {'items':objects}, selected, namespaces


class TopologyTest(unittest.TestCase):
    def setUp(self):
        self.objects,self.selected,self.namespaces=fixtures()
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()

    def test_projection_has_ready_bound_services_and_separate_image_identities(self):
        result=project(self.objects,self.selected)
        self.assertEqual(set(result['components']),set(self.selected['components']))
        self.assertEqual(set(result['services']),{'web','api','database','storage'})
        pod=result['components']['api']['pods'][0]
        self.assertEqual(pod['declared_reference'],PIN)
        self.assertEqual(pod['runtime_image_id'],RUNTIME)
        self.assertNotEqual(PIN.rsplit('@',1)[1],pod['runtime_digest'])
        self.assertNotIn('secret',json.dumps(result))
        self.assertEqual(result['services']['api']['target_pod_uids'],[pod['uid']])
        self.assertEqual(scope(self.namespaces,'incident-app')['namespace'],'incident-app')

    def test_nonworker_role_controller_kinds_do_not_add_a_hidden_deployment_requirement(self):
        objects,selected,_=fixtures(dict(web='Pod',api='DaemonSet',database='StatefulSet',storage='ReplicaSet'))
        result=project(objects,selected)
        self.assertEqual(result['components']['web']['kind'],'Pod')
        self.assertEqual(result['components']['api']['kind'],'DaemonSet')
        self.assertEqual(result['components']['database']['kind'],'StatefulSet')
        self.assertEqual(result['components']['storage']['kind'],'ReplicaSet')

    def test_api_may_serve_web_while_worker_stays_a_separate_deployment(self):
        self.selected['components']['web']=dict(self.selected['components']['api'])
        api_pod=next(v for v in self.objects['items'] if v['kind']=='Pod' and v['metadata']['name']=='api-pod')
        endpoint=next(v for v in self.objects['items'] if v['kind']=='EndpointSlice' and v['metadata']['name']=='web-endpoints')
        endpoint['endpoints'][0].update(addresses=[api_pod['status']['podIP']],targetRef=dict(kind='Pod',namespace='incident-app',name='api-pod',uid=api_pod['metadata']['uid']))
        result=project(self.objects,self.selected)
        self.assertEqual(result['components']['web']['uid'],result['components']['api']['uid'])
        self.assertNotEqual(result['components']['worker']['uid'],result['components']['api']['uid'])

    def test_incomplete_ownership_readiness_endpoints_and_image_ids_refuse(self):
        for mode in ('duplicate','foreign-namespace','terminating','missing-rs','stale-generation',
                     'pending','unready-container','missing-image','bad-image','no-endpoints',
                     'foreign-endpoint','wrong-address','wrong-service-owner','node-port','public-ip'):
            objects=copy.deepcopy(self.objects)
            pod=next(v for v in objects['items'] if v['kind']=='Pod' and v['metadata']['name']=='api-pod')
            controller=next(v for v in objects['items'] if v['kind']=='Deployment' and v['metadata']['name']=='api')
            service=next(v for v in objects['items'] if v['kind']=='Service' and v['metadata']['name']=='api')
            endpoint=next(v for v in objects['items'] if v['kind']=='EndpointSlice' and v['metadata']['name']=='api-endpoints')
            if mode=='duplicate':objects['items'].append(copy.deepcopy(pod))
            elif mode=='foreign-namespace':pod['metadata']['namespace']='other'
            elif mode=='terminating':pod['metadata']['deletionTimestamp']='now'
            elif mode=='missing-rs':objects['items']=[v for v in objects['items'] if not (v['kind']=='ReplicaSet' and v['metadata']['name']=='api-rs')]
            elif mode=='stale-generation':controller['status']['observedGeneration']=0
            elif mode=='pending':pod['status']['phase']='Pending'
            elif mode=='unready-container':pod['status']['containerStatuses'][0]['ready']=False
            elif mode=='missing-image':pod['status']['containerStatuses'][0]['imageID']=''
            elif mode=='bad-image':pod['spec']['containers'][0]['image']='user:secret@registry/image'
            elif mode=='no-endpoints':endpoint['endpoints']=[]
            elif mode=='foreign-endpoint':endpoint['endpoints'][0]['targetRef']['uid']=str(uuid.uuid4())
            elif mode=='wrong-address':endpoint['endpoints'][0]['addresses']=['10.42.0.100']
            elif mode=='wrong-service-owner':endpoint['metadata']['ownerReferences'][0]['uid']=str(uuid.uuid4())
            elif mode=='node-port':service['spec']['type']='NodePort'
            else:service['spec']['clusterIP']='8.8.8.8'
            with self.subTest(mode=mode),self.assertRaises(ValueError):project(objects,self.selected)

    def prefix(self, source=None):
        source=source or ('import json,sys; print(json.dumps('+repr(self.namespaces)+' if "namespaces" in sys.argv else '+repr(self.objects)+')); print("secret-diagnostic",file=sys.stderr)')
        helper=self.root/('query-'+uuid.uuid4().hex+'.py')
        helper.write_text(source)
        return [sys.executable,str(helper)]

    def probe(self,prefix):
        return subprocess.run([sys.executable,'-m','evaluation.topology_probe','--mapping',json.dumps(self.selected),
                               '--kubectl-prefix',json.dumps(prefix)],capture_output=True,text=True,timeout=10)

    def test_actual_subprocess_queries_are_bracketed_and_raw_secret_values_are_not_logged(self):
        result=self.probe(self.prefix())
        self.assertEqual(result.returncode,0,result.stdout)
        value=json.loads(result.stdout)
        self.assertEqual(value['query_exit_codes'],[0,0,0,0])
        self.assertEqual(value['outcome'],'stable_topology_observed')
        self.assertNotIn('secret',result.stdout+result.stderr)

    def test_failed_query_reports_original_status_without_raw_diagnostics(self):
        result=self.probe(self.prefix('import sys; print("secret-body"); print("secret-diagnostic",file=sys.stderr); sys.exit(7)'))
        self.assertEqual(result.returncode,1)
        self.assertEqual(json.loads(result.stdout)['query_exit_codes'],[7])
        self.assertNotIn('secret',result.stdout+result.stderr)

    def test_topology_drift_between_real_queries_is_incomplete(self):
        with tempfile.TemporaryDirectory() as temp:
            counter=Path(temp)/'count'
            source=('import json,sys; from pathlib import Path; p=Path('+repr(str(counter))+'); '
                    'n=int(p.read_text()) if p.exists() else 0; p.write_text(str(n+1)); '
                    'value='+repr(self.namespaces)+' if "namespaces" in sys.argv else '+repr(self.objects)+'; '
                    'value["items"][0]["metadata"]["uid"]="'+str(uuid.uuid4())+'" if n>=2 else value["items"][0]["metadata"]["uid"]; print(json.dumps(value))')
            result=self.probe(self.prefix(source))
        self.assertEqual(result.returncode,1)
        self.assertEqual(json.loads(result.stdout)['outcome'],'topology_observation_incomplete')

    def test_transport_honors_lifetime_and_keeps_sanitized_receipt(self):
        reserves=[]
        class Box:
            def exec_argv(self,argv):return [sys.executable,*argv[1:]]
        with tempfile.TemporaryDirectory() as temp, Attempt(Path(temp)/'logs',{}) as attempt:
            value=capture_topology(attempt,Box(),kubectl_prefix=self.prefix(),selected=self.selected,
                                   lifetime_check=lambda reserve:reserves.append(reserve) or True)
            self.assertEqual(value['outcome'],'stable_topology_observed')
            self.assertTrue((attempt.directory/'foundation-topology.json').exists())
            self.assertEqual(reserves,[70,0])
            with self.assertRaises(Inconclusive):
                capture_topology(attempt,Box(),kubectl_prefix=self.prefix(),selected=self.selected,lifetime_check=lambda reserve:False)
