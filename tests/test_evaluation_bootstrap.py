"""Repeat bootstrap cannot escape scope or grade stale/missing observations."""
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from evaluation.bootstrap import repeat_bootstrap
from evaluation.evidence import Attempt


class BootstrapTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.calls=[];self.allowed=True
        self.box=SimpleNamespace(name='factory-eval-grader-0123456789abcdef',project=self.root/'project',stopped=False,creation_attempted=True)
        self.box.exec_argv=lambda command:['sbx','exec','-w',str(self.box.project),self.box.name]+command
        directory=self.root/'guard';directory.mkdir()
        self.guard=SimpleNamespace(directory=directory,process=SimpleNamespace(poll=lambda:None))
    def run_check(self, **changes):
        def observe(box,**deadlines):
            self.calls.append('observe');self.assertEqual(set(deadlines),{'monotonic_deadline','wall_deadline'})
            return {'independent':1}
        def verify(before,after,expected):
            self.calls.append('verify');self.assertEqual(before,after)
        def command(attempt,label,argv,**options):
            self.calls.append('command');self.assertEqual(argv,self.box.exec_argv(['./ops/bootstrap.sh']))
            self.assertGreater(options['timeout'],0);self.assertLessEqual(options['timeout'],30)
            return {'outcome':'passed','exit_code':0}
        options=dict(observe=observe,verify=verify,expected_case={'id':'independent'},source_check=lambda reserve:self.allowed,
                     monotonic_deadline=time.monotonic()+60,wall_deadline=time.time()+60,timeout=30,command_runner=command)
        options.update(changes)
        with Attempt(self.root/'logs',{}) as attempt:
            result=repeat_bootstrap(attempt,self.box,self.guard,**options)
        self.assertEqual(json.loads((self.root/'logs/repeat-bootstrap-result.json').read_text()),result)
        return result
    def test_preservation_checked_only_after_scoped_command(self):
        result=self.run_check();self.assertEqual(result['verdict'],'pass');self.assertFalse(result['abort_suite'])
        self.assertEqual(self.calls,['observe','verify','command','observe','verify'])
    def test_precondition_assertion_does_not_become_application_failure(self):
        def verify(*args):raise AssertionError('private-precondition')
        result=self.run_check(verify=verify);self.assertEqual(result['verdict'],'inconclusive');self.assertTrue(result['abort_suite'])
        self.assertNotIn('command',self.calls);self.assertNotIn('private-precondition',str(result))
    def test_after_command_mismatch_is_fail_and_aborts(self):
        calls=[]
        def verify(*args):
            calls.append(True)
            if len(calls)==2:raise AssertionError('private-resource')
        result=self.run_check(verify=verify);self.assertEqual(result['verdict'],'fail');self.assertTrue(result['abort_suite'])
        self.assertTrue(result['preservation_mismatch_observed']);self.assertNotIn('private-resource',str(result))
    def test_command_failure_preserves_exit_status_and_does_not_observe_after(self):
        result=self.run_check(command_runner=lambda *args,**kwargs:{'outcome':'failed','exit_code':7})
        self.assertEqual(result['verdict'],'inconclusive');self.assertEqual(result['command_exit_code'],7)
        self.assertEqual(self.calls,['observe','verify'])
    def test_command_timeout_is_inconclusive(self):
        result=self.run_check(command_runner=lambda *args,**kwargs:{'outcome':'timeout','exit_code':-15})
        self.assertEqual(result['verdict'],'inconclusive');self.assertTrue(result['abort_suite'])
    def test_lost_guard_never_runs_command(self):
        self.guard.process.poll=lambda:1
        result=self.run_check();self.assertEqual(result['verdict'],'inconclusive');self.assertEqual(self.calls,[])
    def test_source_change_after_command_cannot_reach_verification(self):
        def command(*args,**kwargs):self.allowed=False;return {'outcome':'passed','exit_code':0}
        result=self.run_check(command_runner=command);self.assertEqual(result['verdict'],'inconclusive');self.assertEqual(self.calls,['observe','verify'])
    def test_host_command_redirect_is_refused(self):
        self.box.exec_argv=lambda command:['sh','./ops/bootstrap.sh']
        result=self.run_check();self.assertEqual(result['verdict'],'inconclusive');self.assertNotIn('command',self.calls)
    def test_observer_error_is_sanitized_and_aborts(self):
        def observe(*args,**kwargs):raise RuntimeError('private-database-credential')
        result=self.run_check(observe=observe);self.assertEqual(result['error_type'],'RuntimeError')
        self.assertNotIn('private-database-credential',str(result));self.assertTrue(result['abort_suite'])
    def test_guard_loss_during_final_verification_revokes_pass(self):
        calls=[]
        def verify(*args):
            calls.append(True)
            if len(calls)==2:(self.guard.directory/'release.json').write_text('{}')
        result=self.run_check(verify=verify);self.assertEqual(result['verdict'],'inconclusive');self.assertTrue(result['abort_suite'])
    def test_source_verification_time_reduces_actual_command_budget(self):
        with patch('evaluation.bootstrap.time.monotonic',return_value=100) as clock:
            def source(reserve):clock.return_value+=5;return True
            def command(*args,**kwargs):
                self.assertEqual(kwargs['timeout'],44)
                return {'outcome':'passed','exit_code':0}
            result=self.run_check(source_check=source,timeout=100,command_runner=command)
        self.assertEqual(result['verdict'],'pass')
    def test_successful_logging_without_successful_exit_cannot_pass(self):
        result=self.run_check(command_runner=lambda *args,**kwargs:{'outcome':'passed','exit_code':7})
        self.assertEqual(result['verdict'],'inconclusive');self.assertTrue(result['abort_suite'])
    def test_final_source_assertion_is_infrastructure_not_preservation_failure(self):
        calls=[]
        def source(reserve):
            calls.append(True)
            if len(calls)==6:raise AssertionError('private-source-diagnostic')
            return True
        result=self.run_check(source_check=source)
        self.assertEqual(result['verdict'],'inconclusive');self.assertNotIn('private-source-diagnostic',str(result))
    def test_guard_revocation_inside_final_source_callback_revokes_pass(self):
        calls=[]
        def source(reserve):
            calls.append(True)
            if len(calls)==6:(self.guard.directory/'release.json').write_text('{}')
            return True
        result=self.run_check(source_check=source)
        self.assertEqual(result['verdict'],'inconclusive');self.assertTrue(result['abort_suite'])
    def test_transport_signal_is_not_application_failure(self):
        result=self.run_check(command_runner=lambda *args,**kwargs:{'outcome':'failed','exit_code':-9})
        self.assertEqual(result['verdict'],'inconclusive');self.assertEqual(result['command_exit_code'],-9)
        self.assertTrue(result['abort_suite'])
    def test_guard_loss_with_mismatch_retains_positive_but_refuses_final_failure_claim(self):
        calls=[]
        def verify(*args):
            calls.append(True)
            if len(calls)==2:
                (self.guard.directory/'release.json').write_text('{}')
                raise AssertionError('private-mismatch')
        result=self.run_check(verify=verify)
        self.assertEqual(result['verdict'],'inconclusive');self.assertTrue(result['preservation_mismatch_observed'])
        self.assertTrue(result['abort_suite']);self.assertNotIn('private-mismatch',str(result))
