"""Planning hashes inputs and exposes isolation/resources without execution."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from evaluation.evidence import atomic_json
from evaluation.plan import build_plan
from evaluation.sandbox import sandbox_create_argv


class PlanTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        self.workload=self.root/'workload';(self.workload/'builder').mkdir(parents=True);(self.workload/'review').mkdir()
        self.suite=self.root/'suite';self.suite.mkdir()
        self.evidence=self.root/'evidence';self.evidence.mkdir()
        self.parent=self.root/'workspaces';self.parent.mkdir()
        packages=[dict(id='WP-001',criteria=['AC-001'])]
        atomic_json(self.workload/'builder/packages.json',dict(packages=packages))
        (self.workload/'builder/APPLICATION.md').write_text('Reviewed fixture workload')
        hashes={str(path.relative_to(self.workload)):hashlib.sha256(path.read_bytes()).hexdigest() for path in (self.workload/'builder').iterdir()}
        atomic_json(self.workload/'review/WORKLOAD-APPROVAL.json',dict(schema_version=1,approval_type='workload_and_envelope_review_not_suite_freeze',approved_scope=['24-hour builder wall-clock ceiling','8-vCPU and 16-GiB sandbox allocation'],workload_sha256=hashes))
        (self.suite/'case.py').write_text('def check(target): pass\n')
        atomic_json(self.suite/'suite.json',dict(schema_version=1,files={'case.py':hashlib.sha256((self.suite/'case.py').read_bytes()).hexdigest()},
            packages_sha256=hashlib.sha256(json.dumps(packages,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            cases=[dict(id='check',source='case.py',function='check',criteria=['AC-001'],timeout_seconds=10)],coverage_complete=[]))

    def plan(self,**kwargs):
        return build_plan(self.workload,self.suite,kwargs.pop('parent',self.parent),self.evidence,port=kwargs.pop('port',18080),**kwargs)

    def test_exact_commands_sequential_origin_and_protected_mounts(self):
        value=self.plan()
        for role,resource in value['resources'].items():
            self.assertEqual(resource['create_argv'],sandbox_create_argv(resource['project'],resource['specification'],name=resource['name'],port=18080,role=role))
            self.assertEqual(resource['create_argv'][-1],resource['specification']+':ro')
            self.assertIn('127.0.0.1:18080:8080',resource['create_argv'])
            self.assertNotIn(str(self.suite),resource['create_argv'])
            self.assertNotIn(str(self.evidence),resource['create_argv'])
            self.assertEqual(resource['manual_stop'],['sbx','stop',resource['name']])
            self.assertFalse(resource['created'])
        self.assertEqual(value['resources']['builder']['host_port'],value['resources']['grader']['host_port'])
        self.assertTrue(any('only after builder termination' in step for step in value['sequence']))

    def test_local_snapshot_plan_binds_both_roles_without_enabling_launch(self):
        templates={role:dict(reference='factory-req007-'+role+':0123456789abcdef',
                   manifest_digest='sha256:'+'a'*64,archive_sha256='b'*64)
                   for role in ('builder','grader')}
        with patch('subprocess.Popen',side_effect=AssertionError('No execution allowed')):
            value=self.plan(templates=templates)
        templates['builder']['reference']='changed:latest'
        self.assertEqual(value['template_bindings'],value['source_identities']['template_bindings'])
        for role,resource in value['resources'].items():
            argv=resource['create_argv']
            self.assertEqual(argv[argv.index('--template')+1],value['template_bindings'][role]['reference'])
            self.assertEqual(argv[argv.index('--pull')+1],'never')
        self.assertFalse(value['launch_enabled'])
        self.assertFalse(Path(value['workspace']).exists())

    def test_incomplete_or_role_mismatched_snapshot_plan_refuses_before_effects(self):
        binding=dict(reference='factory-req007-builder:0123456789abcdef',
                     manifest_digest='sha256:'+'a'*64,archive_sha256='b'*64)
        for templates in ({},{'builder':binding},{'builder':binding,'grader':binding},
                          {'builder':None,'grader':None}):
            with self.subTest(templates=templates), self.assertRaises(ValueError):
                self.plan(templates=templates)
        self.assertEqual(list(self.parent.iterdir()),[])

    def test_plan_has_no_process_network_or_workspace_effects(self):
        before=set(self.root.rglob('*'))
        with patch('subprocess.Popen',side_effect=AssertionError('Unexpected process')):
            value=self.plan()
        self.assertEqual(set(self.root.rglob('*')),before)
        self.assertFalse(Path(value['workspace']).exists())
        self.assertFalse(value['launch_enabled'])
        self.assertEqual(value['outcome'],'planned_not_ready')
        self.assertEqual(value['changes_made']['model_calls'],0)
        self.assertFalse(value['changes_made']['policy_changed'])
        self.assertEqual(value['readiness']['outcome'],'not_ready')

    def test_changed_workload_and_suite_are_refused(self):
        for path in (self.workload/'builder/APPLICATION.md',self.suite/'case.py'):
            original=path.read_bytes();path.write_bytes(original+b'changed')
            with self.assertRaises(ValueError):self.plan()
            path.write_bytes(original)
        self.assertEqual(list(self.parent.iterdir()),[])

    def test_project_root_inside_protected_input_or_evidence_is_refused(self):
        for parent in (self.workload,self.suite,self.evidence,Path(__file__).resolve().parents[1]):
            with self.subTest(parent=parent):
                with self.assertRaises(ValueError):self.plan(parent=parent)

    def test_existing_workspace_collision_is_retained(self):
        existing=self.parent/'factory-eval-0123456789abcdef';existing.mkdir();(existing/'owned').write_text('retain')
        with patch('evaluation.plan.uuid.uuid4',return_value=SimpleNamespace(hex='0123456789abcdef0123456789abcdef')):
            with self.assertRaises(ValueError):self.plan()
        self.assertEqual((existing/'owned').read_text(),'retain')

    def test_invalid_ports_and_mode_separator_cannot_make_commands(self):
        for port in (True,0,1023,65536,18080.0):
            with self.assertRaises(ValueError):self.plan(port=port)
        parent=self.root/'colon:workspace';parent.mkdir()
        with self.assertRaises(ValueError):self.plan(parent=parent)

    def test_current_hashes_and_approval_scope_are_explicit(self):
        value=self.plan()
        identities=value['source_identities']
        self.assertEqual(identities['suite_sha256'],hashlib.sha256((self.suite/'suite.json').read_bytes()).hexdigest())
        self.assertIn('evaluation/plan.py',identities['controller'])
        self.assertEqual(value['limits']['builder_seconds'],dict(value=86400,approval='D-048'))
        self.assertEqual(value['limits']['grading_seconds']['approval'],'proposal')

    def test_cli_records_plan_but_rejects_launch_switch(self):
        repository=Path(__file__).resolve().parents[1]
        command=[sys.executable,'-m','evaluation','plan','--workload',str(self.workload),'--suite',str(self.suite),'--workspace-parent',str(self.parent),'--port','18080']
        value=subprocess.run(command,cwd=repository,capture_output=True,text=True,timeout=15)
        self.assertEqual(value.returncode,0,value.stderr)
        directory=Path(value.stdout.split('Logs: ',1)[1].splitlines()[0])
        report=json.loads((directory/'plan.json').read_text())
        self.assertFalse(report['launch_enabled']);self.assertFalse(Path(report['workspace']).exists())
        self.assertEqual(json.loads((directory/'result.json').read_text()),report)
        refused=subprocess.run(command+['--execute'],cwd=repository,capture_output=True,text=True,timeout=15)
        self.assertEqual(refused.returncode,2)

    def test_changed_input_during_hashing_cannot_produce_a_plan(self):
        from evaluation.grading import sha256
        target=self.workload/'builder/APPLICATION.md'
        def racing_hash(path):
            value=sha256(path)
            if Path(path)==target:target.write_text('Changed during planning')
            return value
        with patch('evaluation.plan.sha256',side_effect=racing_hash):
            with self.assertRaises(ValueError):self.plan()
        self.assertEqual(list(self.parent.iterdir()),[])

    def test_unapproved_envelope_cannot_be_labelled_D048(self):
        path=self.workload/'review/WORKLOAD-APPROVAL.json'
        value=json.loads(path.read_text());value['approved_scope']=[];atomic_json(path,value)
        with self.assertRaises(ValueError):self.plan()

    def test_approval_change_after_scope_validation_cannot_produce_a_plan(self):
        from evaluation.readiness import audit
        path=self.workload/'review/WORKLOAD-APPROVAL.json'
        changed=False
        def racing_audit(*args,**kwargs):
            nonlocal changed
            if not changed:
                value=json.loads(path.read_text());value['approved_scope']=[]
                atomic_json(path,value);changed=True
            return audit(*args,**kwargs)
        with patch('evaluation.plan.audit',side_effect=racing_audit):
            with self.assertRaises(ValueError):self.plan()
        self.assertEqual(list(self.parent.iterdir()),[])

    def test_new_controller_source_during_inspection_cannot_be_omitted(self):
        from evaluation.grading import sha256
        repository=self.root/'controller';(repository/'evaluation').mkdir(parents=True)
        first=repository/'evaluation/first.py';first.write_text('fixture = 1\n')
        (repository/'pyproject.toml').write_text('fixture')
        (repository/'uv.lock').write_text('fixture')
        changed=False
        def racing_hash(path):
            nonlocal changed
            value=sha256(path)
            if Path(path)==first and not changed:
                (repository/'evaluation/new.py').write_text('fixture = 2\n');changed=True
            return value
        with patch('evaluation.plan.sha256',side_effect=racing_hash):
            with self.assertRaises(ValueError):self.plan(repository=repository)
        self.assertEqual(list(self.parent.iterdir()),[])

    def test_removed_controller_source_during_inspection_cannot_be_retained(self):
        from evaluation.grading import sha256
        repository=self.root/'controller';(repository/'evaluation').mkdir(parents=True)
        first=repository/'evaluation/first.py';first.write_text('fixture = 1\n')
        (repository/'pyproject.toml').write_text('fixture')
        (repository/'uv.lock').write_text('fixture')
        def racing_hash(path):
            value=sha256(path)
            if Path(path)==first:first.unlink()
            return value
        with patch('evaluation.plan.sha256',side_effect=racing_hash):
            with self.assertRaises(ValueError):self.plan(repository=repository)
        self.assertEqual(list(self.parent.iterdir()),[])


class StagedPlanTest(unittest.TestCase):
    plan = PlanTest.plan

    def setUp(self):
        PlanTest.setUp(self)
        path = self.suite/'suite.json'
        manifest = json.loads(path.read_text())
        second = dict(manifest['cases'][0]); second['id'] = 'second'
        manifest['cases'].append(second); atomic_json(path, manifest)
        self.assignments = [dict(id='journey',case_ids=['check']),
                            dict(id='sample',case_ids=['second'])]

    def test_staged_plan_lists_exact_distinct_resources_without_effects(self):
        before = set(self.root.rglob('*'))
        with patch('subprocess.Popen',side_effect=AssertionError('No execution')):
            value = self.plan(stage_assignments=self.assignments)
        self.assertEqual(set(self.root.rglob('*')),before)
        self.assertEqual(set(value['resources']),{'builder','grader-journey','grader-sample'})
        self.assertNotIn('grader-project',value['paths'])
        self.assertEqual(len({r['name'] for r in value['resources'].values()}),3)
        for stage in value['grading_stages']:
            resource = value['resources'][stage['resource']]
            self.assertEqual(resource['create_argv'],sandbox_create_argv(
                resource['project'],resource['specification'],name=resource['name'],port=18080,role='grader'))
            self.assertFalse(Path(resource['project']).exists())
            self.assertEqual(stage['lane'],0)
        self.assertEqual(value['grading_lanes'],[
            {'lane':0,'host_port':18080,'stage_ids':['journey','sample']}])
        self.assertFalse(value['launch_enabled'])
        self.assertEqual(value['limits']['grading_seconds']['value'],5400)
        self.assignments[0]['case_ids'].append('second')
        self.assertEqual(value['grading_stages'][0]['case_ids'],['check'])

    def test_invalid_stage_partition_refuses_before_effects(self):
        for assignments in ([], [{'id':'journey','case_ids':['check']}],
                [{'id':'journey','case_ids':['check','second']},{'id':'sample','case_ids':['second']}],
                [{'id':'journey','case_ids':['check']},{'id':'journey','case_ids':['second']}],
                [{'id':'../escape','case_ids':['check','second']}],
                [{'id':'journey','case_ids':['unknown']}],
                [{'id':'journey','case_ids':['check','second'],'target':{}}],
                [{'id':'journey','case_ids':['check'],'lane':True},{'id':'sample','case_ids':['second']}],
                [{'id':'journey','case_ids':['check'],'lane':32},{'id':'sample','case_ids':['second']}]):
            with self.subTest(assignments=assignments):
                with self.assertRaises(ValueError):self.plan(stage_assignments=assignments)
        self.assertEqual(list(self.parent.iterdir()),[])

    def test_registry_order_is_preserved_within_each_stage(self):
        value = self.plan(stage_assignments=[dict(id='all',case_ids=['second','check'])])
        self.assertEqual(value['grading_stages'][0]['case_ids'],['check','second'])

    def test_parallel_lanes_receive_distinct_deterministic_ports(self):
        assignments=[dict(id='journey',case_ids=['check'],lane=1),
                     dict(id='sample',case_ids=['second'],lane=0)]
        value=self.plan(stage_assignments=assignments)
        self.assertEqual(value['grading_lanes'],[
            {'lane':0,'host_port':18080,'stage_ids':['sample']},
            {'lane':1,'host_port':18081,'stage_ids':['journey']}])
        self.assertEqual(value['resources']['grader-journey']['host_port'],18081)
        self.assertIn('127.0.0.1:18081:8080',
                      value['resources']['grader-journey']['create_argv'])
        with self.assertRaises(ValueError):
            self.plan(port=65535,stage_assignments=assignments)

    def test_cli_records_staged_assignment(self):
        path = self.root/'assignments.json';atomic_json(path,self.assignments)
        command = [sys.executable,'-m','evaluation','plan','--workload',str(self.workload),
            '--suite',str(self.suite),'--workspace-parent',str(self.parent),'--port','18080',
            '--stage-assignments',str(path)]
        result = subprocess.run(command,capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        directory = Path(result.stdout.split('Logs: ',1)[1].splitlines()[0])
        value = json.loads((directory/'plan.json').read_text())
        self.assertEqual([s['id'] for s in value['grading_stages']],['journey','sample'])
        self.assertFalse(Path(value['workspace']).exists())
