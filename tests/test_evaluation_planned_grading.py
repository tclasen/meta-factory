"""Exact inspected stage resources survive the owned workspace runtime handoff."""
import copy
import json
from pathlib import Path
import shutil
import unittest

import test_evaluation_plan as plan_fixtures
from test_evaluation_grading_stages import FakeGuard, FakeSandbox
from evaluation.evidence import Attempt, atomic_json
from evaluation.grading import Suite
from evaluation.verdicts import Inconclusive
from evaluation.plan import build_plan
from evaluation.planned_grading import grade_planned_stages
from evaluation.sandbox import capture_tree
from evaluation.workspace import prepare_workspace, verify_prepared_workspace


class PlannedGradingTest(unittest.TestCase):
    def setUp(self):
        plan_fixtures.StagedPlanTest.setUp(self)
        self.preparation = Attempt(self.root/'preparation-evidence', {})
        self.addCleanup(self.preparation.close)
        self.plan = build_plan(self.workload, self.suite, self.parent, self.evidence,
                               port=18080, stage_assignments=self.assignments,
                               templates=getattr(self, 'templates', None))
        self.suite = Suite(self.suite, json.loads((self.workload/'builder/packages.json').read_text())['packages'])
        for function in (prepare_workspace, verify_prepared_workspace):
            function(self.preparation, self.plan, self.workload, self.suite.root,
                monotonic_deadline=100, wall_deadline=100, monotonic=lambda:10, wall=lambda:10)
        builder = Path(self.plan['paths']['builder-project'])
        (builder/'ops').mkdir(); (builder/'ops/bootstrap.sh').write_text('#!/bin/sh\nexit 0\n')
        self.inventory = capture_tree(builder, self.plan['paths']['capture'], termination_verified=True)
        self.configurations = [dict(id=stage['id'], target={}) for stage in self.plan['grading_stages']]
        FakeSandbox.instances=[]; FakeSandbox.events=[]; FakeSandbox.stop_verified=True
        FakeGuard.release_verified=True

    def run_grading(self, attempt, **options):
        defaults = dict(termination_verified=True, monotonic_deadline=100,
            wall_deadline=100, monotonic=lambda:10, wall=lambda:10, development=True,
            sandbox_factory=FakeSandbox, guard_factory=FakeGuard,
            command_runner=lambda *args,**kwargs:dict(outcome='passed',exit_code=0))
        defaults.update(options)
        return grade_planned_stages(attempt,self.preparation,self.plan,self.workload,
            self.suite,self.configurations,self.inventory,**defaults)

    def test_actual_child_execution_uses_inspected_names_projects_and_assignments(self):
        with Attempt(self.root/'grading-evidence',{}) as attempt:
            result = self.run_grading(attempt)
            receipt = json.loads((attempt.directory/'planned-grading-binding.json').read_text())
            intent = json.loads((attempt.directory/'grading-stages-intent.json').read_text())
        self.assertTrue(result['protocol_valid']); self.assertFalse(result['project_success'])
        self.assertEqual(set(result['case_results']),{'check','second'})
        self.assertEqual(receipt['stage_ids'],['journey','sample'])
        self.assertEqual([value['verdict'] for value in result['case_results'].values()],['pass','pass'])
        self.assertEqual([action for action,name in FakeSandbox.events],['create','release','create','release'])
        for stage in intent['stages']:
            resource = self.plan['resources']['grader-'+stage['id']]
            self.assertEqual(stage['sandbox'],resource['name'])
            self.assertEqual(stage['project'],resource['project'])
            self.assertEqual(stage['create_argv'],resource['create_argv'])
        self.assertEqual(intent['grading_seconds'],5400)

    def test_plan_or_configuration_override_refuses_before_sandbox_creation(self):
        original = copy.deepcopy(self.plan); configs = copy.deepcopy(self.configurations)
        for index,mode in enumerate(('name','case','port','budget','configuration','order','termination')):
            self.plan = copy.deepcopy(original); self.configurations = copy.deepcopy(configs)
            options = {}
            if mode=='name':self.plan['resources']['grader-journey']['name']='factory-eval-grader-'+'0'*16
            elif mode=='case':self.plan['grading_stages'][0]['case_ids']=['second']
            elif mode=='port':options['port']=18081
            elif mode=='budget':options['grading_seconds']=1
            elif mode=='configuration':self.configurations[0]['name']='override'
            elif mode=='order':self.configurations.reverse()
            else:options['termination_verified']=False
            with self.subTest(mode=mode),Attempt(self.root/('invalid-'+str(index)),{}) as attempt:
                with self.assertRaises(ValueError):self.run_grading(attempt,**options)
                self.assertFalse((attempt.directory/'grading-stages-intent.json').exists())
        self.assertEqual(FakeSandbox.instances,[])

    def test_parallel_lane_plan_executes_with_inspected_ports_and_resources(self):
        assignments=[dict(id='journey',case_ids=['check'],lane=1),
                     dict(id='sample',case_ids=['second'],lane=0)]
        plan=build_plan(self.workload,self.suite.root,self.parent,self.evidence,
                        port=18080,stage_assignments=assignments)
        with Attempt(self.root/'parallel-preparation',{}) as preparation:
            for function in (prepare_workspace,verify_prepared_workspace):
                function(preparation,plan,self.workload,self.suite.root,
                    monotonic_deadline=100,wall_deadline=100,
                    monotonic=lambda:10,wall=lambda:10)
            builder=Path(plan['paths']['builder-project'])
            (builder/'ops').mkdir();(builder/'ops/bootstrap.sh').write_text('#!/bin/sh\nexit 0\n')
            inventory=capture_tree(builder,plan['paths']['capture'],termination_verified=True)
            configurations=[dict(id=stage['id'],target={}) for stage in plan['grading_stages']]
            with Attempt(self.root/'parallel-grading',{}) as attempt:
                result=grade_planned_stages(attempt,preparation,plan,self.workload,self.suite,
                    configurations,inventory,termination_verified=True,
                    monotonic_deadline=100,wall_deadline=100,
                    monotonic=lambda:10,wall=lambda:10,development=True,
                    sandbox_factory=FakeSandbox,guard_factory=FakeGuard,
                    command_runner=lambda *args,**kwargs:dict(outcome='passed',exit_code=0))
                intent=json.loads((attempt.directory/'grading-lanes-intent.json').read_text())
        self.assertTrue(result['protocol_valid'])
        self.assertEqual(set(result['case_results']),{'check','second'})
        self.assertEqual({lane['port'] for lane in intent['lanes']},{18080,18081})
        self.assertEqual({box.port for box in FakeSandbox.instances},{18080,18081})
        self.assertTrue(all(box.stopped for box in FakeSandbox.instances))

    def test_missing_or_modified_reinspection_receipt_refuses_handoff(self):
        path = self.preparation.directory/'workspace-verification.json'
        original = path.read_bytes()
        for index,mode in enumerate(('missing','preparation-hash','plan-hash','outcome')):
            path.write_bytes(original)
            if mode=='missing':path.unlink()
            else:
                value=json.loads(original)
                value[{'preparation-hash':'preparation_sha256','plan-hash':'plan_sha256','outcome':'outcome'}[mode]]='changed'
                atomic_json(path,value)
            with self.subTest(mode=mode),Attempt(self.root/('receipt-'+str(index)),{}) as attempt:
                with self.assertRaises((ValueError,FileNotFoundError)):self.run_grading(attempt)
        self.assertEqual(FakeSandbox.instances,[])

    def test_original_workspace_replacement_refuses_even_with_same_bytes(self):
        builder = Path(self.plan['paths']['builder-project'])
        builder.rename(builder.with_name('moved-builder'))
        builder.mkdir(mode=0o700)
        with Attempt(self.root/'replaced-builder',{}) as attempt:
            with self.assertRaises(Inconclusive):self.run_grading(attempt)
        self.assertEqual(FakeSandbox.instances,[])

    def test_midstage_receipt_drift_retains_raw_pass_and_blocks_later_creation(self):
        def loader(box, **context):
            self.assertIs(context['lifetime_check'](),True)
            path = self.preparation.directory/'workspace-verification.json'
            value = json.loads(path.read_text()); value['extra']='changed'
            atomic_json(path,value)
            return dict(accounts={})
        self.configurations[0]['options'] = dict(fixture_loader=loader)
        with Attempt(self.root/'receipt-drift',{}) as attempt:
            result = self.run_grading(attempt)
            raw = json.loads((attempt.directory/'journey/stage-observations.json').read_text())
        self.assertFalse(result['protocol_valid']); self.assertTrue(result['aborted'])
        self.assertEqual(len(FakeSandbox.instances),1)
        self.assertTrue(FakeSandbox.instances[0].stopped)
        self.assertEqual(raw['case_results']['check']['verdict'],'pass')
        self.assertEqual(result['case_results']['check']['verdict'],'inconclusive')
        self.assertEqual(result['case_results']['check']['observed_verdict'],'pass')

    def test_reviewed_specification_drift_refuses_before_creation(self):
        path = Path(self.plan['paths']['specification'])/'APPLICATION.md'
        path.chmod(0o644); path.write_text('changed reviewed specification'); path.chmod(0o444)
        with Attempt(self.root/'specification-drift',{}) as attempt:
            with self.assertRaises(ValueError):self.run_grading(attempt)
        self.assertEqual(FakeSandbox.instances,[])

    def test_midstage_capture_root_replacement_with_identical_bytes_invalidates_handoff(self):
        def loader(box, **context):
            capture = Path(self.plan['paths']['capture'])
            moved = self.root/'previous-capture'
            capture.rename(moved); shutil.copytree(moved,capture)
            return dict(accounts={})
        self.configurations[0]['options'] = dict(fixture_loader=loader)
        with Attempt(self.root/'capture-replacement',{}) as attempt:
            result = self.run_grading(attempt)
        self.assertFalse(result['protocol_valid'])
        self.assertEqual(len(FakeSandbox.instances),1)
        self.assertTrue(FakeSandbox.instances[0].stopped)
        self.assertEqual(result['case_results']['check']['observed_verdict'],'pass')

    def test_cached_approval_cannot_differ_from_independently_loaded_review(self):
        self.suite.approved=True
        with Attempt(self.root/'cached-approval',{}) as attempt:
            with self.assertRaises(ValueError):self.run_grading(attempt)
        self.assertEqual(FakeSandbox.instances,[])

    def test_outer_clock_expiry_or_invalidity_refuses_before_creation(self):
        for index,clock in enumerate((100,float('nan'),True)):
            with self.subTest(clock=clock),Attempt(self.root/('clock-'+str(index)),{}) as attempt:
                with self.assertRaises(Inconclusive):self.run_grading(attempt,wall=lambda:clock)
        self.assertEqual(FakeSandbox.instances,[])


class SnapshotPlannedGradingTest(unittest.TestCase):
    setUp = PlannedGradingTest.setUp
    run_grading = PlannedGradingTest.run_grading
    templates = {role:dict(reference='factory-req007-'+role+':0123456789abcdef',
                 manifest_digest='sha256:'+'a'*64, archive_sha256='b'*64)
                 for role in ('builder','grader')}

    def test_snapshot_is_preserved_from_inspection_through_every_child_creation(self):
        with Attempt(self.root/'snapshot-grading',{}) as attempt:
            report = self.run_grading(attempt)
            intent = json.loads((attempt.directory/'grading-stages-intent.json').read_text())
        self.assertTrue(report['protocol_valid'])
        self.assertEqual(len(FakeSandbox.instances),2)
        for stage, box in zip(intent['stages'], FakeSandbox.instances):
            self.assertEqual(box.template,self.templates['grader'])
            self.assertEqual(stage['create_argv'],
                             self.plan['resources']['grader-'+stage['id']]['create_argv'])
            self.assertIn('--pull',stage['create_argv'])

    def test_removed_or_changed_snapshot_refuses_before_child_creation(self):
        original = copy.deepcopy(self.plan)
        for index, mode in enumerate(('removed','digest','command')):
            self.plan = copy.deepcopy(original)
            if mode == 'removed':del self.plan['template_bindings']
            elif mode == 'digest':self.plan['template_bindings']['grader']['manifest_digest']='sha256:'+'c'*64
            else:self.plan['resources']['grader-journey']['create_argv'].remove('--pull')
            with self.subTest(mode=mode), Attempt(self.root/('snapshot-invalid-'+str(index)),{}) as attempt:
                with self.assertRaises(ValueError):self.run_grading(attempt)
        self.assertEqual(FakeSandbox.instances,[])
