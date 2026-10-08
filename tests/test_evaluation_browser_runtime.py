"""REQ-012/015/021: protected mounts, privilege checks, and peer lease failure."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from evaluation.browser_relay import serve
from evaluation.browser_runtime import BrowserExecutor, VOLUME_OPTIONS, shared_json, verify_container, verify_volume
from evaluation.grading import sha256


class BrowserRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy = self.root / 'seccomp.json'; self.policy.write_text('{"defaultAction":"SCMP_ACT_ERRNO"}')
        self.options = dict(image='sha256:'+'1'*64, seccomp=self.policy, seccomp_sha256=sha256(self.policy),
                            network='2'*64, peer_host='172.20.0.3', peer_port=8080, peer_check=lambda: None)
        self.mounts = [(self.root / 'source', '/protected'), (self.root / 'output', '/output')]
        self.record = dict(id='3'*64, owner='4'*32, image=self.options['image'], user='1000:1000', network='none',
            readonly=True, privileged=False, cap_drop=['ALL'], cap_add=None, pid_mode='', init=True,
            ipc_mode='private', log_driver='none', memory=1024**3, cpus=2000000000, pids=256, shm=256*1024**2,
            security=['no-new-privileges', 'seccomp='+self.policy.read_text()],
            mounts=[dict(Type='bind',Source=str(source),Destination=destination,RW=destination=='/output') for source,destination in self.mounts]
                   +[dict(Type='volume',Name='channel',Destination='/channel',RW=False)])

    def verify(self, record):
        verify_container(record, identifier='3'*64, nonce='4'*32, image=self.options['image'], network='none',
                         mounts=self.mounts, volume='channel', browser=True, seccomp=json.loads(self.policy.read_text()))

    def test_exact_container_projection_passes(self):
        self.verify(self.record)

    def test_changed_privileges_identity_and_bounds_refused(self):
        for key, value in [('id', '5'*64), ('owner','wrong'), ('image','other'), ('user','0'), ('network','host'),
                           ('readonly',False), ('privileged',True), ('cap_drop',[]), ('cap_add',['SYS_ADMIN']),
                           ('pid_mode','host'), ('init',False), ('ipc_mode','host'), ('log_driver','json-file'),
                           ('memory',0), ('cpus',0), ('pids',-1), ('shm',0), ('security',['no-new-privileges','seccomp={}'])]:
            with self.subTest(field=key), self.assertRaises(ValueError):
                self.verify(dict(self.record, **{key:value}))

    def test_mount_widening_replacement_and_duplicates_refused(self):
        for mutate in (lambda mounts: mounts[0].update(RW=True),
                       lambda mounts: mounts[0].update(Source='/unrelated'),
                       lambda mounts: mounts[2].update(RW=True),
                       lambda mounts: mounts[2].update(Name='other'),
                       lambda mounts: mounts.append(dict(mounts[0])),
                       lambda mounts: mounts[1].update(Destination='/protected')):
            record=deepcopy(self.record); mutate(record['mounts'])
            with self.assertRaises(ValueError): self.verify(record)

    def test_mutable_or_unguarded_operator_configuration_refused(self):
        for key,value in [('image','latest'), ('network','host'), ('peer_host','localhost'), ('peer_port',True),
                          ('peer_check',None), ('seccomp_sha256','0'*64)]:
            with self.subTest(field=key), self.assertRaises(ValueError):
                BrowserExecutor(**dict(self.options, **{key:value}))

    def test_insufficient_budget_never_creates_resources(self):
        executor=BrowserExecutor(**self.options)
        with patch('evaluation.browser_runtime.collect') as collect, patch('evaluation.browser_runtime.BrowserGuard') as guard:
            result=executor(None,None,{'id':'case'}, {},timeout_seconds=135)
        collect.assert_not_called(); guard.assert_not_called()
        self.assertEqual(result['verdict'],'inconclusive')
        self.assertFalse(result['guard_verified'])

    def test_socket_volume_collision_or_configuration_change_refused(self):
        value=dict(name='channel',owner='nonce',driver='local',options=VOLUME_OPTIONS,created='fixture-time')
        self.assertEqual(verify_volume(value,'channel','nonce'),'fixture-time')
        for key, changed in [('owner','unrelated'), ('name','other'), ('driver','plugin'), ('options',{}), ('created','')]:
            with self.subTest(field=key), self.assertRaises(ValueError):
                verify_volume(dict(value, **{key:changed}),'channel','nonce')

    def test_readable_lease_is_published_without_temporary_files(self):
        path=self.root/'lease.json'
        shared_json(path,{'nonce':'first'}); shared_json(path,{'nonce':'second'})
        self.assertEqual(json.loads(path.read_text()),{'nonce':'second'})
        self.assertEqual(path.stat().st_mode & 0o777,0o444)
        self.assertFalse(path.with_name('.lease.json.next').exists())

    def test_relay_expiry_and_wrong_nonce_never_start_transport(self):
        lease=self.root/'lease';lease.mkdir();out=self.root/'out';out.mkdir()
        config=dict(nonce='expected',wall_deadline=time.time()+5,upstream={},authority='127.0.0.1:18080')
        for value in ({'nonce':'expected','expires_at':time.time()-1}, {'nonce':'other','expires_at':time.time()+2},
                      {'nonce':'expected','expires_at':time.time()+100}):
            shared_json(lease/'lease.json',value)
            with patch('evaluation.browser_relay.RelayServer') as factory:
                self.assertEqual(serve(config,lease,out),1)
                factory.assert_not_called()
            self.assertFalse(json.loads((out/'result.json').read_text())['closed'])
            result=json.loads((out/'result.json').read_text())
            self.assertEqual(result['failure_phase'],'initial_lease')
            self.assertEqual(result['failure_kind'],'exception')

    def test_relay_lease_diagnostics_do_not_expose_invalid_contents(self):
        lease=self.root/'lease';lease.mkdir();out=self.root/'out';out.mkdir()
        config=dict(nonce='expected',wall_deadline=time.time()+5,upstream={},authority='127.0.0.1:18080')
        for value,kind in [('secret invalid json','invalid_json'), ('{"nonce":"expected"}','invalid_field')]:
            (lease/'lease.json').write_text(value)
            with patch('evaluation.browser_relay.RelayServer') as factory:
                self.assertEqual(serve(config,lease,out),1)
                factory.assert_not_called()
            result=json.loads((out/'result.json').read_text())
            self.assertEqual(result['failure_phase'],'initial_lease')
            self.assertEqual(result['failure_kind'],kind)
            self.assertNotIn('secret',json.dumps(result))

    def test_relay_missing_shared_lease_waits_only_for_current_valid_receipt(self):
        lease=self.root/'lease';lease.mkdir();out=self.root/'out';out.mkdir()
        config=dict(nonce='expected',wall_deadline=time.time()+5,upstream={},authority='127.0.0.1:18080')
        receipt=json.dumps({'nonce':'expected','expires_at':time.time()+2})
        stop=json.dumps({'nonce':'expected'})
        shared_json(lease/'stop.json',{'nonce':'expected'})
        with patch('pathlib.Path.read_text',side_effect=[FileNotFoundError(),receipt,receipt,stop]), \
                patch('evaluation.browser_relay.RelayServer') as factory:
            factory.return_value.observation.return_value={}
            self.assertEqual(serve(config,lease,out),0)
        for replacement in (json.dumps({'nonce':'expected','expires_at':time.time()-1}),
                            json.dumps({'nonce':'wrong','expires_at':time.time()+2})):
            with patch('pathlib.Path.read_text',side_effect=[FileNotFoundError(),replacement]), \
                    patch('evaluation.browser_relay.RelayServer') as factory:
                self.assertEqual(serve(config,lease,out),1)
                factory.assert_not_called()
        with patch('pathlib.Path.read_text',side_effect=FileNotFoundError()), \
                patch('evaluation.browser_relay.time.monotonic',side_effect=[0,.2]), \
                patch('evaluation.browser_relay.RelayServer') as factory:
            self.assertEqual(serve(config,lease,out),1)
            factory.assert_not_called()
        result=json.loads((out/'result.json').read_text())
        self.assertEqual(result['failure_kind'],'missing_file')

    def test_relay_stop_identity_and_cleanup_failure_remain_inconclusive(self):
        lease=self.root/'lease';lease.mkdir();out=self.root/'out';out.mkdir()
        config=dict(nonce='expected',wall_deadline=time.time()+5,upstream={},authority='127.0.0.1:18080')
        for nonce, broken in [('expected',False),('other',False),('expected',True)]:
            shared_json(lease/'lease.json',{'nonce':'expected','expires_at':time.time()+2})
            shared_json(lease/'stop.json',{'nonce':nonce})
            with patch('evaluation.browser_relay.RelayServer') as factory:
                relay=factory.return_value;relay.observation.return_value={'completed':1}
                if broken:relay.server_close.side_effect=RuntimeError('secret')
                status=serve(config,lease,out)
            result=json.loads((out/'result.json').read_text())
            self.assertEqual(result['closed'],nonce=='expected' and not broken)
            self.assertEqual(status,0 if result['closed'] else 1)
            self.assertNotIn('secret',json.dumps(result))
