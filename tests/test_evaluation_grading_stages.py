"""Fresh projects, one exact registry partition and fail-closed stage settlement."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest

from evaluation.evidence import Attempt, atomic_json
from evaluation.grading import Suite
from evaluation.grading_stages import grade_lanes, grade_stages
from evaluation.sandbox import capture_tree, sandbox_create_argv


class FakeSandbox:
    instances = []
    events = []
    stop_verified = True
    def __init__(self, attempt, project, specification, controller, **kwargs):
        self.attempt=attempt;self.project=project;self.specification=specification
        self.name=kwargs['planned_name'];self.port=kwargs['port']
        self.template=kwargs.get('template')
        self.creation_attempted=False;self.stopped=False
        self.instances.append(self)
    def create_argv(self):
        return sandbox_create_argv(self.project,self.specification,name=self.name,port=self.port,role='grader',template=self.template)
    def create(self):
        self.events.append(('create',self.name))
        self.creation_attempted=True
        atomic_json(self.attempt.directory/'grader-resource.json',dict(name=self.name,project=str(self.project),
                    specification=str(self.specification),manual_stop=['sbx','stop',self.name],port=self.port,
                    primary_workspace=None,project_readonly=False))
        return {'outcome':'passed'}
    def exec_argv(self,args):return ['synthetic-sbx',self.name]+args
    def stop(self):
        self.events.append(('stop',self.name));self.stopped=self.stop_verified;return self.stopped


class FakeGuard:
    release_verified = True
    def __init__(self, directory, name, **kwargs):
        self.directory=Path(directory);self.directory.mkdir()
        self.process=SimpleNamespace(poll=lambda:None);self.nonce='0'*32;self.name=name
        atomic_json(self.directory/'config.json',dict(schema_version=1,sandbox=name,owner_pid=os.getpid(),
                    nonce=self.nonce,max_seconds=6000,expires_at=time.time()+6000))
    def release(self):
        FakeSandbox.events.append(('release',self.name))
        return {'remote_termination_verified':self.release_verified}


class GradingStagesTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        source=self.root/'source';(source/'ops').mkdir(parents=True)
        (source/'ops/bootstrap.sh').write_text('#!/bin/sh\nexit 0\n')
        self.source=self.root/'capture';self.inventory=capture_tree(source,self.source,termination_verified=True)
        self.specification=self.root/'specification';self.specification.mkdir()
        suite_root=self.root/'suite';suite_root.mkdir();self.cases=suite_root/'cases.py'
        self.cases.write_text('def good(target):\n    assert target["value"] == 1, "wrong value"\n')
        packages=[dict(id='WP-001',criteria=['AC-001']),dict(id='WP-012',criteria=['AC-034'])]
        manifest=dict(schema_version=1,packages_sha256=hashlib.sha256(json.dumps(packages,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            files={'cases.py':hashlib.sha256(self.cases.read_bytes()).hexdigest()},cases=[dict(id='journey',source='cases.py',function='good',criteria=['AC-034'],timeout_seconds=2,mutates_shared_state=True),dict(id='sample',source='cases.py',function='good',criteria=['AC-001'],timeout_seconds=2,mutates_shared_state=True)],coverage_complete=['AC-001','AC-034'])
        atomic_json(suite_root/'suite.json',manifest)
        approval=self.root/'fixture-review.json';atomic_json(approval,dict(suite_sha256=hashlib.sha256((suite_root/'suite.json').read_bytes()).hexdigest(),decision='approved',reviewer='fixture reviewer',reviewed_at='fixture'))
        self.suite=Suite(suite_root,packages,approval=approval)
        self.stages=[dict(id='journey',name='factory-eval-grader-'+('0'*16),project=self.root/'journey-project',case_ids=['journey'],target={'value':1}),dict(id='sample',name='factory-eval-grader-'+('1'*16),project=self.root/'sample-project',case_ids=['sample'],target={'value':1})]
        FakeSandbox.instances=[];FakeSandbox.events=[];FakeSandbox.stop_verified=True;FakeGuard.release_verified=True
    def run_stages(self, attempt, **kwargs):
        return grade_stages(attempt,self.source,self.inventory,self.specification,self.suite,self.stages,
                            port=18080,sandbox_factory=FakeSandbox,guard_factory=FakeGuard,
                            command_runner=lambda *args,**kwargs:dict(outcome='passed',exit_code=0),
                            stop_resource=lambda attempt,name,sbx:dict(remote_termination_verified=next(box for box in FakeSandbox.instances if box.name==name).stop()),**kwargs)
    def simulated_deployment(self, attempt, source, inventory, specification, project, suite, target, **kwargs):
        capture_tree(source,project,termination_verified=True)
        box=kwargs['sandbox_factory'](attempt,project,specification,Path(__file__).resolve().parents[1],port=kwargs['port'],role='grader')
        box.create();box.stop()
        case=next(case for case in suite.cases if case['id']==attempt.directory.name)
        values={case['id']:dict(case_id=case['id'],verdict='pass')}
        return dict(suite.aggregate(values),case_results=values,selected_case_ids=[case['id']],aborted=False,
                    outcome='grading_incomplete',cleanup={'remote_termination_verified':True},manual_stop=['sbx','stop',box.name])
    def test_stage_bridge_selection_reaches_deployment(self):
        observed=[]
        for stage in self.stages:stage['options']={'loopback_bridge':True}
        def deployment(*args,**kwargs):
            observed.append(kwargs['loopback_bridge'])
            return self.simulated_deployment(*args,**kwargs)
        with Attempt(self.root/'bridge-options',{}) as attempt:
            report=self.run_stages(attempt,deployment=deployment)
        self.assertEqual(observed,[True,True])
        self.assertTrue(report['protocol_valid'])

    def test_malformed_stage_bridge_selection_refuses_before_creation(self):
        for index,value in enumerate((1,'true',None,{})):
            self.stages[0]['options']={'loopback_bridge':value}
            with Attempt(self.root/('bridge-invalid-'+str(index)),{}) as attempt:
                with self.assertRaises(ValueError):self.run_stages(attempt)
                self.assertFalse((attempt.directory/'grading-stages-intent.json').exists())
            self.assertEqual(FakeSandbox.instances,[])

    def test_actual_child_stages_are_fresh_and_previous_cleanup_precedes_next_create(self):
        def loader(box,**context):
            self.assertIs(context['lifetime_check'](),True)
            generated=box.project/'generated-data'
            self.assertFalse(generated.exists());generated.write_text(box.name)
            return {'accounts':{}}
        for stage in self.stages:stage['options']={'fixture_loader':loader}
        with Attempt(self.root/'logs',{}) as attempt:report=self.run_stages(attempt)
        self.assertTrue(report['project_success']);self.assertTrue(report['protocol_valid'])
        self.assertEqual(report['accepted_packages'],['WP-001','WP-012'])
        self.assertEqual(set(report['case_results']),{'journey','sample'})
        self.assertEqual([event[0] for event in FakeSandbox.events],['create','release','create','release'])
        self.assertNotEqual(FakeSandbox.instances[0].project,FakeSandbox.instances[1].project)
        self.assertEqual((self.root/'journey-project/generated-data').read_text(),self.stages[0]['name'])
        self.assertEqual((self.root/'sample-project/generated-data').read_text(),self.stages[1]['name'])
    def test_unapproved_registry_never_accepts_across_stages(self):
        self.suite=Suite(self.suite.root,self.suite.packages)
        with Attempt(self.root/'development',{}) as attempt:report=self.run_stages(attempt,development=True)
        self.assertFalse(report['project_success']);self.assertEqual(report['accepted_packages'],[])
        self.assertEqual(report['development_passing_packages'],['WP-001','WP-012'])
    def test_shared_failure_stops_new_deployments_and_retains_untested_cases(self):
        self.stages[0]['target']['value']=2
        with Attempt(self.root/'failure',{}) as attempt:report=self.run_stages(attempt)
        self.assertTrue(report['aborted']);self.assertTrue(report['protocol_valid'])
        self.assertEqual(report['criteria']['AC-034']['verdict'],'fail')
        self.assertEqual(report['criteria']['AC-001']['verdict'],'untested')
        self.assertEqual(len(FakeSandbox.instances),1)
    def test_cleanup_failure_revokes_results_and_prevents_port_reuse(self):
        FakeGuard.release_verified=False;FakeSandbox.stop_verified=False
        with Attempt(self.root/'cleanup-failure',{}) as attempt:report=self.run_stages(attempt)
        self.assertFalse(report['protocol_valid']);self.assertFalse(report['project_success'])
        self.assertEqual(report['accepted_packages'],[]);self.assertEqual(len(FakeSandbox.instances),1)
        self.assertEqual(report['case_results']['journey']['verdict'],'inconclusive')
        self.assertEqual(report['case_results']['journey']['observed_verdict'],'pass')
        self.assertFalse(report['stages'][0]['termination_verified'])
    def test_shared_dual_clock_budget_does_not_reset_between_stages(self):
        current={'mono':10,'wall':100};allowances=[]
        def deploy(*args,**kwargs):
            allowances.append(kwargs['grading_seconds'])
            result=self.simulated_deployment(*args,**kwargs)
            current['mono']+=3;current['wall']+=5
            return result
        with Attempt(self.root/'budget',{}) as attempt:
            report=self.run_stages(attempt,deployment=deploy,grading_seconds=12,
                                   monotonic=lambda:current['mono'],wall=lambda:current['wall'])
        self.assertEqual(allowances,[12,7]);self.assertTrue(report['project_success'])
        self.assertEqual(report['monotonic_elapsed_seconds'],6);self.assertEqual(report['wall_elapsed_seconds'],10)

    def test_stage_specific_ports_bind_creation_deployment_and_intent(self):
        self.stages[0]['port']=18081
        observed=[]
        def deploy(*args,**kwargs):
            observed.append(kwargs['port'])
            return self.simulated_deployment(*args,**kwargs)
        with Attempt(self.root/'ports',{}) as attempt:
            report=self.run_stages(attempt,deployment=deploy)
            intent=json.loads((attempt.directory/'grading-stages-intent.json').read_text())
        self.assertTrue(report['protocol_valid'])
        self.assertEqual(observed,[18081,18080])
        self.assertEqual([stage['port'] for stage in intent['stages']],[18081,18080])
        self.assertIn('127.0.0.1:18081:8080',intent['stages'][0]['create_argv'])

    def test_independent_lanes_overlap_and_aggregate_one_registry(self):
        barrier = threading.Barrier(2)
        active = set(); overlapped = []
        lock = threading.Lock()
        stages = copy.deepcopy(self.stages)
        for lane, stage in enumerate(stages):
            stage.update(lane=lane, port=18080 + lane)
        def deploy(*args, **kwargs):
            with lock:
                active.add(args[0].directory.name)
                overlapped.append(len(active))
            barrier.wait(timeout=2)
            result = self.simulated_deployment(*args, **kwargs)
            with lock: active.remove(args[0].directory.name)
            return result
        with Attempt(self.root/'parallel',{}) as attempt:
            report = grade_lanes(attempt,self.source,self.inventory,self.specification,
                self.suite,stages,port=18080,deployment=deploy,
                sandbox_factory=FakeSandbox,guard_factory=FakeGuard,
                command_runner=lambda *args,**kwargs:dict(outcome='passed',exit_code=0),
                stop_resource=lambda attempt,name,sbx:dict(remote_termination_verified=True))
            intent=json.loads((attempt.directory/'grading-lanes-intent.json').read_text())
        self.assertTrue(report['protocol_valid']);self.assertTrue(report['project_success'])
        self.assertEqual(set(report['case_results']),{'journey','sample'})
        self.assertIn(2,overlapped)
        self.assertEqual([lane['port'] for lane in intent['lanes']],[18080,18081])

    def test_lane_port_alias_refuses_before_creation(self):
        stages = copy.deepcopy(self.stages)
        for lane, stage in enumerate(stages):stage.update(lane=lane,port=18080)
        with Attempt(self.root/'aliased-lanes',{}) as attempt,self.assertRaises(ValueError):
            grade_lanes(attempt,self.source,self.inventory,self.specification,
                        self.suite,stages,port=18080)
        self.assertEqual(FakeSandbox.instances,[])

    def test_stages_remain_sequential_inside_one_lane(self):
        stages = copy.deepcopy(self.stages)
        for stage in stages:stage.update(lane=3,port=18083)
        with Attempt(self.root/'one-lane',{}) as attempt:
            report=grade_lanes(attempt,self.source,self.inventory,self.specification,
                self.suite,stages,port=18080,deployment=self.simulated_deployment,
                sandbox_factory=FakeSandbox,guard_factory=FakeGuard,
                command_runner=lambda *args,**kwargs:dict(outcome='passed',exit_code=0),
                stop_resource=lambda attempt,name,sbx:dict(remote_termination_verified=True))
        self.assertTrue(report['project_success'])
        self.assertEqual([event[0] for event in FakeSandbox.events],
                         ['create','stop','create','stop'])

    def test_one_unsettled_lane_revokes_other_lane_observations(self):
        stages = copy.deepcopy(self.stages)
        for lane, stage in enumerate(stages):stage.update(lane=lane,port=18080+lane)
        def deploy(*args,**kwargs):
            result=self.simulated_deployment(*args,**kwargs)
            if args[0].directory.name=='journey':result['manual_stop']=['sbx','stop','wrong']
            return result
        with Attempt(self.root/'lane-failure',{}) as attempt:
            report=grade_lanes(attempt,self.source,self.inventory,self.specification,
                self.suite,stages,port=18080,deployment=deploy,
                sandbox_factory=FakeSandbox,guard_factory=FakeGuard,
                command_runner=lambda *args,**kwargs:dict(outcome='passed',exit_code=0),
                stop_resource=lambda attempt,name,sbx:dict(remote_termination_verified=True))
        self.assertFalse(report['protocol_valid']);self.assertFalse(report['project_success'])
        self.assertEqual(report['case_results']['sample']['verdict'],'inconclusive')
        self.assertEqual(report['case_results']['sample']['observed_verdict'],'pass')
        self.assertTrue(all(box.stopped for box in FakeSandbox.instances))

    def test_shared_lane_deadline_expiry_revokes_all_observations(self):
        stages = copy.deepcopy(self.stages)
        for lane, stage in enumerate(stages):stage.update(lane=lane,port=18080+lane)
        current={'mono':10,'wall':100}; lock=threading.Lock(); barrier=threading.Barrier(2)
        def deploy(*args,**kwargs):
            result=self.simulated_deployment(*args,**kwargs)
            barrier.wait(timeout=2)
            with lock:current['wall']=106
            return result
        with Attempt(self.root/'lane-expiry',{}) as attempt:
            report=grade_lanes(attempt,self.source,self.inventory,self.specification,
                self.suite,stages,port=18080,grading_seconds=5,deployment=deploy,
                monotonic=lambda:current['mono'],wall=lambda:current['wall'],
                sandbox_factory=FakeSandbox,guard_factory=FakeGuard,
                command_runner=lambda *args,**kwargs:dict(outcome='passed',exit_code=0),
                stop_resource=lambda attempt,name,sbx:dict(remote_termination_verified=True))
        self.assertFalse(report['protocol_valid']);self.assertFalse(report['project_success'])
        self.assertEqual(set(report['case_results']),{'journey','sample'})
        self.assertTrue(all(value['verdict']=='inconclusive'
                            for value in report['case_results'].values()))

    def test_lane_interruption_settles_resources_records_and_propagates(self):
        stages = copy.deepcopy(self.stages)
        for lane, stage in enumerate(stages):stage.update(lane=lane,port=18080+lane)
        def deploy(attempt,source,inventory,specification,project,suite,target,**kwargs):
            if attempt.directory.name!='journey':
                return self.simulated_deployment(attempt,source,inventory,specification,
                                                  project,suite,target,**kwargs)
            capture_tree(source,project,termination_verified=True)
            box=kwargs['sandbox_factory'](attempt,project,specification,
                Path(__file__).resolve().parents[1],port=kwargs['port'],role='grader')
            box.create()
            raise KeyboardInterrupt()
        with Attempt(self.root/'lane-interruption',{}) as attempt:
            with self.assertRaises(KeyboardInterrupt):
                grade_lanes(attempt,self.source,self.inventory,self.specification,
                    self.suite,stages,port=18080,deployment=deploy,
                    sandbox_factory=FakeSandbox,guard_factory=FakeGuard,
                    command_runner=lambda *args,**kwargs:dict(outcome='passed',exit_code=0),
                    stop_resource=lambda attempt,name,sbx:dict(remote_termination_verified=
                        next(box for box in FakeSandbox.instances if box.name==name).stop()))
            report=json.loads((attempt.directory/'grading-lanes-result.json').read_text())
        self.assertFalse(report['protocol_valid']);self.assertFalse(report['project_success'])
        self.assertEqual(report['case_results']['sample']['observed_verdict'],'pass')
        self.assertTrue(all(box.stopped for box in FakeSandbox.instances))
    def test_wall_expiry_and_invalid_clock_after_first_stage_revoke_acceptance(self):
        for index,clock in enumerate((120,float('nan'),True,90)):
            current={'wall':100}
            def deploy(*args,**kwargs):
                result=self.simulated_deployment(*args,**kwargs);current['wall']=clock;return result
            with Attempt(self.root/('clock-'+str(index)),{}) as attempt:
                report=self.run_stages(attempt,deployment=deploy,grading_seconds=10,monotonic=lambda:10,wall=lambda:current['wall'])
            self.assertFalse(report['protocol_valid']);self.assertFalse(report['project_success'])
            self.assertEqual(len(report['stages']),1)
            if clock != 120:
                self.assertIsNone(report['monotonic_elapsed_seconds'])
                self.assertIsNone(report['wall_elapsed_seconds'])
            for stage in self.stages:
                if Path(stage['project']).exists():
                    import shutil
                    shutil.rmtree(stage['project'])
    def test_changed_common_capture_or_suite_after_stage_invalidates_observations(self):
        for index,kind in enumerate(('capture','suite')):
            original_source=(self.source/'ops/bootstrap.sh').read_bytes();original_case=self.cases.read_bytes()
            def deploy(*args,**kwargs):
                result=self.simulated_deployment(*args,**kwargs)
                (self.source/'ops/bootstrap.sh' if kind=='capture' else self.cases).write_text('changed common identity')
                return result
            with Attempt(self.root/('identity-'+str(index)),{}) as attempt:report=self.run_stages(attempt,deployment=deploy)
            self.assertFalse(report['protocol_valid']);self.assertEqual(len(report['stages']),1)
            self.assertEqual(report['case_results']['journey']['verdict'],'inconclusive')
            (self.source/'ops/bootstrap.sh').write_bytes(original_source);self.cases.write_bytes(original_case)
            import shutil
            shutil.rmtree(self.stages[0]['project'])
    def test_invalid_partition_or_resources_refuse_before_intent_or_creation(self):
        original=copy.deepcopy(self.stages)
        variations=[]
        missing=copy.deepcopy(original);missing.pop();variations.append(missing)
        duplicate=copy.deepcopy(original);duplicate[1]['case_ids']=['journey'];variations.append(duplicate)
        unknown=copy.deepcopy(original);unknown[1]['case_ids']=['unknown'];variations.append(unknown)
        same_name=copy.deepcopy(original);same_name[1]['name']=same_name[0]['name'];variations.append(same_name)
        same_project=copy.deepcopy(original);same_project[1]['project']=same_project[0]['project'];variations.append(same_project)
        override=copy.deepcopy(original);override[0]['options']={'grading_seconds':999};variations.append(override)
        malformed=copy.deepcopy(original);malformed[0]['options']=[];variations.append(malformed)
        for index,stages in enumerate(variations):
            self.stages=stages
            with Attempt(self.root/('invalid-'+str(index)),{}) as attempt,self.assertRaises(ValueError):self.run_stages(attempt)
            self.assertFalse((attempt.directory/'grading-stages-intent.json').exists())
        self.assertEqual(FakeSandbox.instances,[])
    def test_existing_project_and_oversized_budget_refuse(self):
        self.stages[0]['project'].mkdir()
        with Attempt(self.root/'existing',{}) as attempt,self.assertRaises(ValueError):self.run_stages(attempt)
        self.stages[0]['project'].rmdir()
        with Attempt(self.root/'oversized',{}) as attempt,self.assertRaises(ValueError):self.run_stages(attempt,grading_seconds=5401)
        self.assertEqual(FakeSandbox.instances,[])
    def test_wrong_stage_results_and_cache_refuse(self):
        for index,mode in enumerate(('case','scope','cache','skip','intent')):
            def deploy(*args,**kwargs):
                result=self.simulated_deployment(*args,**kwargs)
                if mode=='case':result['case_results']={'sample':dict(case_id='sample',verdict='pass')}
                elif mode=='scope':result['manual_stop']=['sbx','stop','unowned-resource']
                elif mode=='cache':args[5].cases[0]['criteria']=['AC-001']
                elif mode=='skip':result['selected_case_ids']=['sample']
                else:(args[0].directory/'grader-resource.json').write_text('{}')
                return result
            with Attempt(self.root/('malformed-'+str(index)),{}) as attempt:report=self.run_stages(attempt,deployment=deploy)
            self.assertFalse(report['protocol_valid']);self.assertFalse(report['project_success'])
            self.assertEqual(len(report['stages']),1)
            import shutil
            shutil.rmtree(self.stages[0]['project'])
    def test_fabricated_passes_without_owned_deployment_cannot_accept(self):
        def fabricated(attempt,source,inventory,specification,project,suite,target,**kwargs):
            values={'journey':dict(case_id='journey',verdict='pass')}
            return dict(suite.aggregate(values),case_results=values,selected_case_ids=['journey'],aborted=False,outcome='grading_incomplete',cleanup={'remote_termination_verified':True},manual_stop=['sbx','stop',self.stages[0]['name']])
        with Attempt(self.root/'fabricated',{}) as attempt:report=self.run_stages(attempt,deployment=fabricated)
        self.assertFalse(report['protocol_valid']);self.assertFalse(report['project_success'])
        self.assertEqual(FakeSandbox.instances,[])
    def test_interruption_disposes_owned_resource_records_and_preserves_interrupt(self):
        def interrupted(attempt,source,inventory,specification,project,suite,target,**kwargs):
            capture_tree(source,project,termination_verified=True)
            box=kwargs['sandbox_factory'](attempt,project,specification,Path(__file__).resolve().parents[1],port=kwargs['port'],role='grader')
            box.create();box.name='unowned-resource';box.creation_attempted=False
            raise KeyboardInterrupt()
        with Attempt(self.root/'interrupted',{}) as attempt,self.assertRaises(KeyboardInterrupt):self.run_stages(attempt,deployment=interrupted)
        result=json.loads((attempt.directory/'grading-stages-result.json').read_text())
        self.assertFalse(result['protocol_valid']);self.assertTrue(result['stages'][0]['fallback_termination_verified'])
        self.assertEqual(FakeSandbox.events[-1],('stop',self.stages[0]['name']))
    def test_interruption_at_final_aggregation_retains_report_and_propagates(self):
        armed = {'interrupt':False}
        def clock():
            if armed['interrupt']:raise KeyboardInterrupt()
            return 10
        with Attempt(self.root/'final-interrupt',{}) as attempt:
            original_emit = attempt.emit
            def emit(source,kind,payload):
                original_emit(source,kind,payload)
                if kind=='stages.aggregate':armed['interrupt']=True
            attempt.emit = emit
            with self.assertRaises(KeyboardInterrupt):
                self.run_stages(attempt,deployment=self.simulated_deployment,monotonic=clock,wall=lambda:100)
        result=json.loads((attempt.directory/'grading-stages-result.json').read_text())
        self.assertFalse(result['protocol_valid']);self.assertFalse(result['project_success'])
        self.assertEqual(len(result['stages']),2)
        self.assertTrue(all(stage['termination_verified'] for stage in result['stages']))
        self.assertIsNone(result['monotonic_elapsed_seconds'])

    def test_planned_name_collision_without_creation_intent_never_stops_occupied_resource(self):
        def collision(attempt,source,inventory,specification,project,suite,target,**kwargs):
            capture_tree(source,project,termination_verified=True)
            kwargs['sandbox_factory'](attempt,project,specification,Path(__file__).resolve().parents[1],port=kwargs['port'],role='grader')
            raise ValueError('Existing planned name')
        with Attempt(self.root/'collision',{}) as attempt:report=self.run_stages(attempt,deployment=collision)
        self.assertFalse(report['protocol_valid']);self.assertEqual(FakeSandbox.events,[])
    def test_wrong_or_linked_cleanup_intent_never_authorizes_stop(self):
        for index, kind in enumerate(('wrong-scope','symlink')):
            def broken(attempt,source,inventory,specification,project,suite,target,**kwargs):
                capture_tree(source,project,termination_verified=True)
                box=kwargs['sandbox_factory'](attempt,project,specification,Path(__file__).resolve().parents[1],port=kwargs['port'],role='grader')
                resource=attempt.directory/'grader-resource.json'
                unrelated=dict(name='factory-eval-grader-'+('f'*16),project=str(project),specification=str(specification),manual_stop=['sbx','stop','unowned-resource'])
                if kind=='wrong-scope':atomic_json(resource,unrelated)
                else:
                    other=attempt.directory/'unrelated.json';atomic_json(other,unrelated);resource.symlink_to(other)
                box.creation_attempted=True
                raise RuntimeError('Untrusted cleanup scope')
            with Attempt(self.root/('cleanup-scope-'+str(index)),{}) as attempt:report=self.run_stages(attempt,deployment=broken)
            self.assertFalse(report['protocol_valid']);self.assertFalse(report['stages'][0]['termination_verified'])
            self.assertEqual(FakeSandbox.events,[])
            import shutil
            shutil.rmtree(self.stages[0]['project'])

    def test_sequence_is_one_shot(self):
        with Attempt(self.root/'one-shot',{}) as attempt:
            first=self.run_stages(attempt)
            self.assertTrue(first['project_success'])
            import shutil
            for stage in self.stages:shutil.rmtree(stage['project'])
            with self.assertRaises(FileExistsError):self.run_stages(attempt)
        self.assertEqual(len(FakeSandbox.instances),2)


if __name__=='__main__':unittest.main()
