import contextlib
from pathlib import Path
import tempfile
import unittest

from evaluation.disposal import verify_disposable_operations
from evaluation.evidence import Attempt


class Process:
    def poll(self):return None
class Guard:
    def __init__(self,path):self.directory=path;path.mkdir();self.process=Process()
class Sandbox:
    def __init__(self,root):
        self.name='factory-eval-grader-0123456789abcdef';self.project=root/'project';self.project.mkdir()
        self.stopped=False;self.creation_attempted=True
    def exec_argv(self,argv):return ['sbx','exec','-w',str(self.project),self.name,*argv]


class DisposalTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.box=Sandbox(self.root);self.guard=Guard(self.root/'guard')
        self.commands=[];self.clock=[10.0]
    def tearDown(self):self.temp.cleanup()
    def observe(self,box,**kwargs):
        return {'owned_present':len(self.commands)<2,'unrelated_uid':'canary-uid'}
    def verify(self,before,after):
        self.assertTrue(before['owned_present']);self.assertFalse(after['owned_present']);self.assertEqual(after['unrelated_uid'],'canary-uid')
    @contextlib.contextmanager
    def setup(self,*args,**kwargs):yield {'known_failure_injected':True,'scope_verified':True}
    def runner(self,attempt,label,argv,**kwargs):
        self.commands.append((label,argv));self.clock[0]+=.1
        return {'outcome':'failed','exit_code':7} if label=='disposable-test-failure' else {'outcome':'passed','exit_code':0}
    def execute(self,name='good',**overrides):
        values=dict(observe=self.observe,verify_destroyed=self.verify,failure_setup=self.setup,
            source_check=lambda reserve:True,monotonic_deadline=100,wall_deadline=100,
            command_runner=self.runner,monotonic=lambda:self.clock[0],wall=lambda:self.clock[0])
        values.update(overrides)
        with Attempt(self.root/name,{}) as attempt:return verify_disposable_operations(attempt,self.box,self.guard,**values)
    def test_failure_then_two_scoped_destroys_pass(self):
        result=self.execute();self.assertEqual(result['verdict'],'pass');self.assertFalse(result['abort_suite'])
        self.assertEqual([value[0] for value in self.commands],['disposable-test-failure','disposable-destroy-first','disposable-destroy-repeat'])
        self.assertTrue(all(value[1][:5]==['sbx','exec','-w',str(self.box.project),self.box.name] for value in self.commands))
    def test_hidden_test_failure_is_fail_and_never_destroys(self):
        def runner(*args,**kwargs):self.commands.append((args[1],args[2]));return {'outcome':'passed','exit_code':0}
        result=self.execute('hidden',command_runner=runner);self.assertEqual(result['verdict'],'fail');self.assertEqual(len(self.commands),1)
    def test_first_and_repeat_destroy_failures_are_fail(self):
        for failed in ('disposable-destroy-first','disposable-destroy-repeat'):
            self.commands=[]
            def runner(attempt,label,argv,**kwargs):
                self.commands.append((label,argv));return {'outcome':'failed','exit_code':9} if label==failed else ({'outcome':'failed','exit_code':7} if label=='disposable-test-failure' else {'outcome':'passed','exit_code':0})
            result=self.execute('fail-'+failed,command_runner=runner);self.assertEqual(result['verdict'],'fail')
    def test_scope_damage_is_fail(self):
        def verify(before,after):raise AssertionError('Unrelated canary changed')
        result=self.execute('scope-damage',verify_destroyed=verify);self.assertEqual(result['verdict'],'fail')
    def test_incomplete_setup_command_and_observation_are_inconclusive(self):
        @contextlib.contextmanager
        def setup(*args,**kwargs):yield {'known_failure_injected':True,'scope_verified':False}
        for index,overrides in enumerate(({'failure_setup':setup},{'source_check':lambda reserve:False},
            {'command_runner':lambda *args,**kwargs:{'outcome':'timeout','exit_code':None}},
            {'observe':lambda *args,**kwargs:(_ for _ in ()).throw(RuntimeError('private'))})):
            self.commands=[];result=self.execute('incomplete-'+str(index),**overrides);self.assertEqual(result['verdict'],'inconclusive')
    def test_guard_deadline_and_command_redirect_refuse(self):
        self.guard.process.poll=lambda:1;self.assertEqual(self.execute('guard-lost')['verdict'],'inconclusive')
        self.guard.process.poll=lambda:None;self.clock[0]=101;self.assertEqual(self.execute('deadline')['verdict'],'inconclusive')
        self.clock[0]=10;self.box.exec_argv=lambda argv:['sbx','exec','wrong',*argv];self.assertEqual(self.execute('redirect')['verdict'],'inconclusive')


if __name__=='__main__':unittest.main()
