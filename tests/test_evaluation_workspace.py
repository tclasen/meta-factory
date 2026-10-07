"""Local planned acquisition preserves source gates and never executes resources."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import test_evaluation_plan as plan_fixtures
from evaluation.evidence import Attempt
from evaluation.plan import build_plan, controller_identities
from evaluation.preparation import prepare_specification
from evaluation.sandbox import Sandbox, sandbox_create_argv
from evaluation.workspace import prepare_workspace,verify_prepared_workspace


class WorkspaceTest(unittest.TestCase):
    def setUp(self):
        plan_fixtures.PlanTest.setUp(self)
        self.attempt=Attempt(self.root/'workspace-evidence',{})
        self.addCleanup(self.attempt.close)
        self.plan=build_plan(self.workload,self.suite,self.parent,self.evidence,port=18080)
        self.workspace=Path(self.plan['workspace']);self.clock=10

    def prepare(self,plan=None):
        return prepare_workspace(self.attempt,self.plan if plan is None else plan,
            self.workload,self.suite,monotonic_deadline=100,wall_deadline=100,
            monotonic=lambda:self.clock,wall=lambda:self.clock)

    def receipt(self):
        return json.loads((self.attempt.directory/'workspace-preparation.json').read_text())

    def verify(self,plan=None):
        return verify_prepared_workspace(self.attempt,self.plan if plan is None else plan,
            self.workload,self.suite,monotonic_deadline=100,wall_deadline=100,
            monotonic=lambda:self.clock,wall=lambda:self.clock)

    def verification_receipt(self):
        return json.loads((self.attempt.directory/'workspace-verification.json').read_text())

    def test_local_snapshots_survive_preparation_and_changed_binding_refuses(self):
        templates={role:dict(reference='factory-req007-'+role+':0123456789abcdef',
                   manifest_digest='sha256:'+'a'*64,archive_sha256='b'*64)
                   for role in ('builder','grader')}
        self.plan=build_plan(self.workload,self.suite,self.parent,self.evidence,port=18080,templates=templates)
        self.workspace=Path(self.plan['workspace'])
        self.assertEqual(self.prepare()['outcome'],'workspace_prepared')
        self.assertEqual(self.verify()['outcome'],'workspace_verified_for_inspection')
        changed=copy.deepcopy(self.plan)
        changed['template_bindings']['builder']['manifest_digest']='sha256:'+'c'*64
        with self.assertRaises(ValueError):self.verify(changed)

    def test_owned_copy_empty_project_and_no_execution(self):
        with patch('subprocess.Popen',side_effect=AssertionError('No execution allowed')):
            result=self.prepare()
        self.assertEqual(result['outcome'],'workspace_prepared')
        self.assertEqual(set(p.name for p in self.workspace.iterdir()),{'builder-project','specification'})
        self.assertEqual(list((self.workspace/'builder-project').iterdir()),[])
        self.assertEqual((self.workspace/'specification/APPLICATION.md').read_bytes(),(self.workload/'builder/APPLICATION.md').read_bytes())
        self.assertFalse((self.workspace/'specification/review').exists())
        self.assertFalse((self.workspace/'capture').exists())
        self.assertFalse((self.workspace/'grader-project').exists())
        self.assertFalse(result['launch_enabled']);self.assertFalse(result['sandboxes_created'])
        self.assertEqual(result['model_calls'],0)
        self.assertEqual(result['readiness_outcome'],'not_ready')
        self.assertEqual(result,self.receipt())

    def test_prepared_builder_command_matches_inspected_resource_exactly(self):
        prepared=self.prepare();resource=self.plan['resources']['builder']
        repository=Path(__file__).resolve().parents[1]
        with patch('subprocess.Popen',side_effect=AssertionError('No provisioning allowed')):
            box=Sandbox(self.attempt,prepared['paths']['builder-project'],
                prepared['paths']['specification'],repository,
                port=resource['host_port'],planned_name=resource['name'])
            self.assertEqual(box.create_argv(),resource['create_argv'])
            self.assertEqual(box.name,resource['name'])
        self.assertFalse(box.creation_attempted)

    def test_acquisition_intent_is_durable_before_directory_creation(self):
        original=Path.mkdir
        def inspect(path,*args,**kwargs):
            if path==self.workspace:
                receipt=self.receipt()
                self.assertTrue(receipt['workspace_creation_attempted'])
                self.assertFalse(receipt['workspace_created'])
                self.assertEqual(receipt['workspace'],str(path))
            return original(path,*args,**kwargs)
        with patch.object(Path,'mkdir',inspect):self.prepare()
        identity=self.workspace.stat()
        self.assertEqual(self.receipt()['workspace_identity'],dict(device=identity.st_dev,inode=identity.st_ino))

    def test_existing_workspace_never_claimed_or_overwritten(self):
        self.workspace.mkdir();(self.workspace/'owned').write_text('retain')
        with self.assertRaises(FileExistsError):self.prepare()
        self.assertEqual((self.workspace/'owned').read_text(),'retain')
        self.assertFalse(self.receipt()['workspace_created'])
        self.assertNotIn('retained_workspace',self.receipt())

    def test_existing_workspace_symlink_never_claimed(self):
        target=self.root/'external';target.mkdir();self.workspace.symlink_to(target,target_is_directory=True)
        with self.assertRaises(ValueError):self.prepare()
        self.assertEqual(list(target.iterdir()),[])
        self.assertFalse((self.attempt.directory/'workspace-preparation.json').exists())

    def test_redirected_paths_and_effects_are_refused(self):
        for mode in ('path','mount','stop','name','allocation','allocation-type','port','created','created-type','launch'):
            plan=copy.deepcopy(self.plan)
            resource=plan['resources']['builder']
            if mode=='path':plan['paths']['specification']=str(self.suite)
            elif mode=='mount':resource['create_argv'][-1]=str(self.suite)
            elif mode=='stop':resource['manual_stop']=['sbx','stop','unrelated']
            elif mode=='name':resource['name']='unrelated'
            elif mode=='allocation':resource['cpus']=1
            elif mode=='allocation-type':resource['cpus']=8.0
            elif mode=='port':resource['host_port']=True
            elif mode=='created':resource['created']=True
            elif mode=='created-type':resource['created']=0
            else:plan['launch_enabled']=True
            with self.subTest(mode=mode):
                with self.assertRaises(ValueError):self.prepare(plan)
                self.assertFalse(self.workspace.exists())

    def test_protected_workspace_overlap_refused(self):
        workspace=self.workload/self.workspace.name
        plan=copy.deepcopy(self.plan);plan['workspace']=str(workspace)
        plan['paths']={name:str(workspace/name) for name in plan['paths']}
        with self.assertRaises(ValueError):self.prepare(plan)
        self.assertFalse(workspace.exists())

    def test_changed_approval_is_refused_before_acquisition(self):
        path=self.workload/'review/WORKLOAD-APPROVAL.json';path.write_bytes(path.read_bytes()+b'\n')
        with self.assertRaises(ValueError):self.prepare()
        self.assertFalse(self.workspace.exists())
        self.assertFalse(self.receipt()['workspace_created'])

    def test_suite_drift_during_copy_retains_owned_workspace(self):
        def change(*args,**kwargs):
            result=prepare_specification(*args,**kwargs)
            (self.suite/'case.py').write_text('changed protected source')
            return result
        with patch('evaluation.workspace.prepare_specification',side_effect=change):
            with self.assertRaises(ValueError):self.prepare()
        self.assertEqual(self.receipt()['outcome'],'workspace_preparation_incomplete')
        self.assertEqual(self.receipt()['retained_workspace'],str(self.workspace))
        self.assertTrue((self.workspace/'specification/APPLICATION.md').exists())

    def test_controller_inventory_drift_revokes_prepared_result(self):
        calls=0
        def changed(repository):
            nonlocal calls
            calls+=1;value=controller_identities(repository)
            if calls==2:value['evaluation/uninspected.py']='0'*64
            return value
        with patch('evaluation.workspace.controller_identities',side_effect=changed):
            with self.assertRaises(ValueError):self.prepare()
        self.assertTrue(self.receipt()['workspace_created'])
        self.assertEqual(self.receipt()['outcome'],'workspace_preparation_incomplete')

    def test_copy_failure_retains_only_owned_paths_and_sanitizes_error(self):
        with patch('evaluation.workspace.prepare_specification',side_effect=OSError('private detail')):
            with self.assertRaises(OSError):self.prepare()
        self.assertEqual(self.receipt()['error_type'],'OSError')
        self.assertNotIn('private detail',json.dumps(self.receipt()))
        self.assertEqual(set(p.name for p in self.workspace.iterdir()),{'builder-project'})

    def test_expiry_before_copy_cannot_succeed_or_be_retried(self):
        self.clock=101
        with self.assertRaises(TimeoutError):self.prepare()
        self.assertFalse(self.workspace.exists())
        with self.assertRaises(FileExistsError):self.prepare()

    def test_expiry_after_copy_retains_workspace_and_revokes_success(self):
        def expire(*args,**kwargs):
            result=prepare_specification(*args,**kwargs);self.clock=101
            return result
        with patch('evaluation.workspace.prepare_specification',side_effect=expire):
            with self.assertRaises(TimeoutError):self.prepare()
        self.assertTrue(self.receipt()['workspace_created'])
        self.assertEqual(self.receipt()['outcome'],'workspace_preparation_incomplete')

    def test_same_plan_cannot_acquire_again_after_success(self):
        result=self.prepare()
        with self.assertRaises(FileExistsError):self.prepare()
        self.assertEqual(self.receipt(),result)

    def test_plan_readiness_drift_cannot_change_inspected_gates(self):
        plan=copy.deepcopy(self.plan);plan['readiness']['blockers']=[]
        with self.assertRaises(ValueError):self.prepare(plan)
        self.assertFalse(self.workspace.exists())

    def test_directory_replacement_and_unexpected_content_revoke_result(self):
        for mode in ('replace','content'):
            with self.subTest(mode=mode):
                with Attempt(self.root/('other-evidence-'+mode),{}) as attempt:
                    plan=build_plan(self.workload,self.suite,self.parent,self.evidence,port=18080)
                    workspace=Path(plan['workspace'])
                    def change(*args,**kwargs):
                        result=prepare_specification(*args,**kwargs)
                        project=workspace/'builder-project'
                        if mode=='replace':
                            project.rename(workspace/'old-project');project.mkdir()
                        else:(project/'unexpected').write_text('unexpected')
                        return result
                    with patch('evaluation.workspace.prepare_specification',side_effect=change):
                        with self.assertRaises(ValueError):
                            prepare_workspace(attempt,plan,self.workload,self.suite,monotonic_deadline=100,wall_deadline=100,monotonic=lambda:10,wall=lambda:10)
                    self.assertEqual(json.loads((attempt.directory/'workspace-preparation.json').read_text())['outcome'],'workspace_preparation_incomplete')

    def test_success_is_one_shot_and_plan_mutation_does_not_change_receipt(self):
        result=self.prepare();self.plan['paths']['capture']='changed'
        self.assertNotEqual(result['paths']['capture'],'changed')
        with self.assertRaises(ValueError):self.prepare()
        self.assertEqual(self.receipt(),result)

    def test_prepared_workspace_reinspection_executes_nothing_and_preserves_receipt(self):
        prepared=self.prepare()
        with patch('subprocess.Popen',side_effect=AssertionError('No execution allowed')):
            result=self.verify()
        self.assertEqual(result['outcome'],'workspace_verified_for_inspection')
        self.assertFalse(result['launch_enabled']);self.assertFalse(result['sandboxes_created'])
        self.assertEqual(result['files'],prepared['specification']['files'])
        self.assertEqual(result,self.verification_receipt())
        self.assertEqual(self.receipt(),prepared)

    def test_changed_prepared_bytes_permissions_and_inventory_refuse_verification(self):
        self.prepare();spec=self.workspace/'specification';path=spec/'APPLICATION.md'
        original=path.read_bytes()
        for mode in ('bytes','file-mode','directory-mode','extra-file','missing-file','hardlink'):
            with self.subTest(mode=mode):
                try:
                    if mode=='bytes':path.chmod(0o600);path.write_bytes(original+b'changed');path.chmod(0o444)
                    elif mode=='file-mode':path.chmod(0o644)
                    elif mode=='directory-mode':spec.chmod(0o755)
                    elif mode=='extra-file':spec.chmod(0o755);(spec/'unreviewed').write_text('unreviewed')
                    elif mode=='missing-file':spec.chmod(0o755);path.unlink()
                    else:
                        import os
                        os.link(path,self.root/'alias')
                    with self.assertRaises(ValueError):self.verify()
                    self.assertEqual(self.verification_receipt()['outcome'],'workspace_verification_incomplete')
                finally:
                    (self.root/'alias').unlink(missing_ok=True)
                    spec.chmod(0o755);(spec/'unreviewed').unlink(missing_ok=True)
                    if path.exists():path.chmod(0o600)
                    path.write_bytes(original);path.chmod(0o444);spec.chmod(0o555)

    def test_same_byte_replacement_of_owned_specification_refuses_verification(self):
        import shutil
        self.prepare();spec=self.workspace/'specification';saved=self.root/'saved-spec'
        spec.chmod(0o755);spec.rename(saved);saved.chmod(0o555);shutil.copytree(saved,spec)
        with self.assertRaises(ValueError):self.verify()

    def test_project_directory_replacement_or_content_refuses_verification(self):
        self.prepare();project=self.workspace/'builder-project'
        (project/'unexpected').write_text('unexpected')
        with self.assertRaises(ValueError):self.verify()
        (project/'unexpected').unlink();project.rename(self.root/'saved-project');project.mkdir(mode=0o700)
        with self.assertRaises(ValueError):self.verify()

    def test_changed_plan_and_source_identity_refuse_verification(self):
        self.prepare();plan=copy.deepcopy(self.plan);plan['limits']['builder_seconds']['value']=1
        with self.assertRaises(ValueError):self.verify(plan)
        (self.suite/'case.py').write_text('changed protected source')
        with self.assertRaises(ValueError):self.verify()

    def test_failed_preparation_never_verifies(self):
        with patch('evaluation.workspace.prepare_specification',side_effect=OSError('private detail')):
            with self.assertRaises(OSError):self.prepare()
        with self.assertRaises(ValueError):self.verify()

    def test_verification_expiry_revokes_current_inspection_preserves_preparation(self):
        prepared=self.prepare();self.verify();self.clock=101
        with self.assertRaises(TimeoutError):self.verify()
        self.assertEqual(self.receipt(),prepared)
        self.assertEqual(self.verification_receipt()['outcome'],'workspace_verification_incomplete')

    def test_verification_receipt_drift_and_duplicate_keys_refuse(self):
        self.prepare();path=self.attempt.directory/'workspace-preparation.json';raw=path.read_bytes()
        from evaluation.preparation import snapshot
        def change(*args,**kwargs):
            result=snapshot(*args,**kwargs);path.write_bytes(raw+b'\n')
            return result
        with patch('evaluation.workspace.snapshot',side_effect=change):
            with self.assertRaises(ValueError):self.verify()
        path.write_bytes(b'{"outcome":"workspace_prepared","outcome":"workspace_prepared"}')
        with self.assertRaises(ValueError):self.verify()


class StagedWorkspaceTest(unittest.TestCase):
    prepare = WorkspaceTest.prepare
    verify = WorkspaceTest.verify
    receipt = WorkspaceTest.receipt

    def setUp(self):
        plan_fixtures.StagedPlanTest.setUp(self)
        self.attempt = Attempt(self.root/'workspace-evidence',{})
        self.addCleanup(self.attempt.close)
        self.clock = 10
        self.plan = build_plan(self.workload,self.suite,self.parent,self.evidence,
                               port=18080,stage_assignments=self.assignments)
        self.workspace = Path(self.plan['workspace'])

    def test_staged_preparation_and_reinspection_leave_all_grader_projects_absent(self):
        with patch('subprocess.Popen',side_effect=AssertionError('No provisioning')):
            prepared = self.prepare(); verified = self.verify()
        self.assertEqual(prepared['outcome'],'workspace_prepared')
        self.assertEqual(verified['outcome'],'workspace_verified_for_inspection')
        for stage in self.plan['grading_stages']:
            resource = self.plan['resources'][stage['resource']]
            self.assertFalse(Path(resource['project']).exists())
            self.assertEqual(sandbox_create_argv(resource['project'],resource['specification'],
                name=resource['name'],port=18080,role='grader'),resource['create_argv'])
        self.assertFalse(prepared['launch_enabled'])

    def test_stage_resource_or_partition_tampering_refuses_before_ownership(self):
        for mode in ('case','missing','reference','name','project','port','mount','created'):
            plan = copy.deepcopy(self.plan)
            stage = plan['grading_stages'][0]; resource = plan['resources'][stage['resource']]
            if mode=='case':stage['case_ids']=['second']
            elif mode=='missing':plan['grading_stages'].pop()
            elif mode=='reference':stage['resource']='grader-sample'
            elif mode=='name':resource['name']=plan['resources']['grader-sample']['name']
            elif mode=='project':resource['project']=str(self.suite)
            elif mode=='port':resource['host_port']=18081
            elif mode=='mount':resource['create_argv'][-1]=str(self.suite)+':ro'
            else:resource['created']=True
            with self.subTest(mode=mode):
                with self.assertRaises(ValueError):self.prepare(plan)
                self.assertFalse(self.workspace.exists())
                self.assertFalse((self.attempt.directory/'workspace-preparation.lock').exists())

    def test_unexpected_stage_project_after_preparation_refuses_reinspection(self):
        self.prepare()
        path = Path(self.plan['resources']['grader-journey']['project']);path.mkdir()
        with self.assertRaises(ValueError):self.verify()
        self.assertTrue(path.exists())

    def test_stage_registry_drift_refuses_acquisition(self):
        (self.suite/'case.py').write_text('changed')
        with self.assertRaises(ValueError):self.prepare()
        self.assertFalse(self.workspace.exists())
