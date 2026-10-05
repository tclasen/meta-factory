"""Running duration bounds cannot survive unknown/replaced/restarted processes."""
import copy
import unittest

from evaluation.faults import FaultSetupError
from evaluation.running_clock import RunningClock


class RunningClockTest(unittest.TestCase):
    def setUp(self):
        self.now = 0;self.checks = []
        self.resources = {role:dict(namespace='incident-app',kind='deployment',name=role,uid=role+'-uid') for role in ('api','worker')}
        self.states = {role:dict(resource,replicas=1,generation=1,observed_generation=1,
            pods=[dict(name=role+'-pod',uid=role+'-pod-uid',running=True,ready=False,terminating=False,process_fingerprint=('a' if role=='api' else 'b')*64)]) for role,resource in self.resources.items()}
        def observe(role):
            self.now += 1
            return copy.deepcopy(self.states[role])
        self.clock = RunningClock(self.resources,observe,lambda:self.checks.append(True),earliest=0,monotonic=lambda:self.now)

    def test_role_interval_intersection_bounds_without_dependency_readiness(self):
        self.assertEqual(self.clock.sample(),{'minimum':0,'maximum':2})
        self.now = 10
        self.assertEqual(self.clock.sample(),{'minimum':8,'maximum':12})
        self.assertEqual(len(self.checks),8)

    def test_replaced_restarted_or_rescaled_workloads_invalidate_permanently(self):
        changes=[lambda s:s.update(uid='replacement'),lambda s:s.update(generation=2,observed_generation=2),
                 lambda s:s['pods'][0].update(uid='replacement'),
                 lambda s:s['pods'][0].update(process_fingerprint='c'*64),
                 lambda s:s['pods'][0].update(running=False),lambda s:s['pods'][0].update(terminating=True)]
        for change in changes:
            self.setUp();self.clock.sample();original=copy.deepcopy(self.states['worker']);change(self.states['worker'])
            with self.assertRaises(FaultSetupError):self.clock.sample()
            self.states['worker']=original
            with self.assertRaises(FaultSetupError):self.clock.sample()

    def test_missing_metadata_duplicate_pods_and_stale_generation_refuse_clock(self):
        changes=[lambda s:s['pods'][0].pop('process_fingerprint'),lambda s:s['pods'][0].update(process_fingerprint='raw-private-id'),
                 lambda s:s.update(observed_generation=0),lambda s:s['pods'].append(copy.deepcopy(s['pods'][0])),
                 lambda s:s.update(replicas=True)]
        for change in changes:
            self.setUp();change(self.states['api'])
            with self.assertRaises(FaultSetupError):self.clock.sample()

    def test_explicit_pause_guard_loss_and_backward_clock_refuse_results(self):
        self.clock.sample();self.clock.invalidate()
        with self.assertRaises(FaultSetupError):self.clock.sample()
        self.setUp();self.clock.sample();self.now=0
        with self.assertRaises(FaultSetupError):self.clock.sample()
        self.setUp()
        def revoked():raise RuntimeError('private-guard-canary')
        self.clock.check=revoked
        with self.assertRaises(FaultSetupError) as raised:self.clock.sample()
        self.assertNotIn('private-guard-canary',str(raised.exception))

    def test_post_observation_guard_loss_suppresses_receipt(self):
        calls=[]
        def check():
            calls.append(True)
            if len(calls)==2:raise RuntimeError('revoked')
        self.clock.check=check
        with self.assertRaises(FaultSetupError):self.clock.sample()
        self.assertTrue(self.clock.invalid)

    def test_reordered_pods_preserve_identity_and_future_earliest_is_refused(self):
        for role in self.states:
            self.states[role]['replicas']=2
            second=copy.deepcopy(self.states[role]['pods'][0]);second.update(name=role+'-second',uid=role+'-second-uid')
            self.states[role]['pods'].append(second)
        self.clock.sample()
        for state in self.states.values():state['pods'].reverse()
        self.now=10;self.assertEqual(self.clock.sample()['minimum'],8)
        with self.assertRaises(FaultSetupError):RunningClock(self.resources,lambda role:{},lambda:None,earliest=100,monotonic=lambda:0)
