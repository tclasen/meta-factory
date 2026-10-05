"""Fresh browser fixtures cannot escape the outer deployment lifetime or origin."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from evaluation.browser import BrowserFixtureUnavailable
from evaluation.browser_binding import BrowserBinding


class BrowserBindingTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.guard=SimpleNamespace(directory=self.root,process=Mock())
        self.guard.process.poll.return_value=None
        self.box=SimpleNamespace(stopped=False)
        self.peer=Mock()
        self.factory=Mock()
        self.config=dict(image='image',seccomp='policy',seccomp_sha256='hash',network='network',
                         peer_host='172.20.0.3',peer_port=8080,peer_check=self.peer,
                         fixtures={'journey':{'accounts':{'analyst':{'password':'private'}},'case_id':'fresh'}})
        self.clock=[10]

    def bind(self):
        return BrowserBinding(self.box,self.guard,self.config,base_url='http://127.0.0.1:18080',
            monotonic_deadline=500,wall_deadline=500,monotonic=lambda:self.clock[0],wall=lambda:self.clock[0],
            executor_factory=self.factory)

    def test_binding_clones_fresh_fixture_and_caps_remaining_deadline(self):
        binding=self.bind();self.config['fixtures']['journey']['case_id']='changed'
        binding(None,None,{'id':'journey'},{'base_url':binding.base_url,'_audit_control':{'secret':'host'},'_job_control':{'secret':'jobs'},'_staging_control':{'secret':'stage'}},timeout_seconds=999)
        args,kwargs=self.factory.return_value.call_args
        self.assertEqual(args[3]['case_id'],'fresh')
        self.assertNotIn('_audit_control',args[3])
        self.assertNotIn('_job_control',args[3])
        self.assertNotIn('_staging_control',args[3])
        self.assertEqual(kwargs['timeout_seconds'],490)
        self.assertNotIn('fixtures',self.factory.call_args.kwargs)

    def test_each_peer_check_brackets_outer_guard_and_supplies_bound(self):
        binding=self.bind()
        callback=self.factory.call_args.kwargs['peer_check']
        callback();self.peer.assert_called_once_with(1)
        self.peer.side_effect=lambda _:setattr(self.box,'stopped',True)
        with self.assertRaises(RuntimeError):callback()

    def test_outer_stop_release_expiry_revocation_and_process_change_refuse(self):
        for mode in ('stopped','dead','release','result','expired','close','owner'):
            with self.subTest(mode=mode):
                self.box.stopped=False;self.guard.process.poll.return_value=None;self.clock[0]=10
                for name in ('release.json','result.json'):(self.root/name).unlink(missing_ok=True)
                binding=self.bind()
                if mode=='stopped':self.box.stopped=True
                elif mode=='dead':self.guard.process.poll.return_value=0
                elif mode in ('release','result'):(self.root/(mode+'.json')).touch()
                elif mode=='expired':self.clock[0]=501
                elif mode=='close':binding.close()
                elif mode=='owner':binding.owner_pid=-1
                with self.assertRaises(RuntimeError):binding.checked_peer()

    def test_missing_fixture_and_budget_are_preconditions_before_resources(self):
        binding=self.bind()
        for case,timeout in [('missing',200),('journey',135)]:
            with self.assertRaises(BrowserFixtureUnavailable):
                binding(None,None,{'id':case},{'base_url':binding.base_url},timeout_seconds=timeout)
        self.factory.return_value.assert_not_called()

    def test_fixture_cannot_replace_endpoint_or_host_capabilities(self):
        for field in ('base_url','_audit_control','_fault_control','_job_control','_staging_control'):
            self.config['fixtures']['journey'][field]='injected'
            with self.assertRaises(ValueError):self.bind()
            del self.config['fixtures']['journey'][field]
        binding=self.bind()
        with self.assertRaises(ValueError):
            binding(None,None,{'id':'journey'},{'base_url':'http://127.0.0.1:9999'},timeout_seconds=200)

    def test_guard_loss_after_executor_cannot_return_success(self):
        binding=self.bind()
        self.factory.return_value.side_effect=lambda *a,**k:setattr(self.box,'stopped',True)
        with self.assertRaises(RuntimeError):
            binding(None,None,{'id':'journey'},{'base_url':binding.base_url},timeout_seconds=200)
