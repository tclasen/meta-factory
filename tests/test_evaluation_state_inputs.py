"""Shared specification binding without introducing a common builder tracker."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from evaluation.git_state import TRACKER_PATH
from evaluation.plan import controller_identities
from evaluation.state_inputs import ARMS, CONTROL_DIGESTS, RESOURCE_PATH, prepare_state_inputs
from evaluation.state_inputs import prepare_reviewed_state_inputs


class StateInputsTest(unittest.TestCase):
    def setUp(self):
        self.files = {'packages.json': json.dumps(dict(schema_version=1,
            specification_version='synthetic-v1', packages=[dict(id='WP-001', title='Frozen package')])).encode(),
            'APPLICATION.md': b'Complete synthetic requirements', 'public/check.py': b'Never execute me'}
        self.expected = {name: hashlib.sha256(data).hexdigest() for name, data in self.files.items()}
        self.controls = dict(model='gpt-6-luna', reasoning_effort='medium', runtime_version='0.160.0',
            **{name: '1' * (40 if name == 'factory_revision' else 64) for name in CONTROL_DIGESTS})
        self.project = dict(owner='fixture-owner', project_number=42, project_id='PVT_fixture',
            fields={'Work package': 'field-work', 'Status': 'field-status',
                    'Progress': 'field-progress', 'Next action': 'field-next'},
            status_options={'Todo': 'option-todo', 'In progress': 'option-progress',
                            'Blocked': 'option-blocked', 'Done': 'option-done'})

    def prepare(self, **kwargs):
        return prepare_state_inputs(kwargs.pop('files', self.files),
                                    kwargs.pop('expected', self.expected),
                                    kwargs.pop('controls', self.controls), **kwargs)

    def test_complete_common_inputs_and_only_assigned_native_state_artifacts(self):
        original = dict(self.files)
        with patch('subprocess.Popen', side_effect=AssertionError('No command or network allowed')):
            report = self.prepare(projects=self.project)
        self.assertEqual(self.files, original)
        self.assertEqual(report['shared']['specification_files'], self.expected)
        self.assertEqual(report['shared']['specification_bytes'], sum(map(len, self.files.values())))
        self.assertEqual(tuple(report['arms']), ARMS)
        self.assertFalse(report['launch_enabled'])
        self.assertEqual(report['arms']['conversation']['initial_files'], {})
        self.assertEqual(set(report['arms']['git-file']['initial_files']), {TRACKER_PATH})
        project_arm = report['arms']['github-projects']
        self.assertEqual(set(project_arm['initial_files']), {RESOURCE_PATH})
        self.assertEqual(json.loads(project_arm['initial_files'][RESOURCE_PATH]), self.project)
        prefixes = set()
        for arm in report['arms'].values():
            self.assertEqual(arm['shared_identity'], report['shared_identity'])
            prefixes.add(arm['prompt'].split('\n\nKeep task')[0] if arm is report['arms']['conversation']
                         else arm['prompt'].split('\n\nUse .factory')[0] if arm is report['arms']['git-file']
                         else arm['prompt'].split('\n\nUse the assigned')[0])
            self.assertEqual(hashlib.sha256(arm['prompt'].encode()).hexdigest(), arm['prompt_sha256'])
            self.assertFalse(arm['launch_enabled'])
            for name, text in arm['initial_files'].items():
                self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), arm['initial_file_sha256'][name])
        self.assertEqual(len(prefixes), 1)
        self.assertIn('whole-attempt runtime usage', report['overhead_policy'])

    def test_unassigned_projects_remains_explicit_and_no_fallback_tracker(self):
        report = self.prepare()
        self.assertFalse(report['projects_resource_assigned'])
        self.assertEqual(report['arms']['github-projects']['initial_files'], {})
        self.assertIn('stop and report', report['arms']['github-projects']['prompt'])
        self.assertFalse(report['arms']['github-projects']['launch_enabled'])

    def test_missing_extra_changed_or_unsafe_specification_is_rejected(self):
        for files, expected in ((dict(self.files, unexpected=b'x'), self.expected),
                                ({'packages.json': self.files['packages.json']}, self.expected),
                                (dict(self.files, **{'APPLICATION.md': b'changed'}), self.expected),
                                (self.files, dict(self.expected, **{'APPLICATION.md': '0' * 64}))):
            with self.subTest(files=files):
                with self.assertRaises(ValueError):
                    self.prepare(files=files, expected=expected)
        for name in ('../escape', '/absolute', 'public//check', 'a\\b', 'a\nStatus: done', '.'):
            with self.subTest(name=name):
                data = dict(self.files, **{name: b'unsafe'})
                expected = {key: hashlib.sha256(value).hexdigest() for key, value in data.items()}
                with self.assertRaises(ValueError):
                    self.prepare(files=data, expected=expected)

    def test_changed_shared_controls_change_identity_and_invalid_controls_fail(self):
        first = self.prepare()
        controls = dict(self.controls, context_configuration_sha256='2' * 64)
        second = self.prepare(controls=controls)
        self.assertNotEqual(first['shared_identity'], second['shared_identity'])
        for updates in (dict(model='substituted-model'), dict(runtime_version='moving-latest'),
                        dict(limits_sha256=None), dict(token='must-not-log-secret')):
            with self.assertRaises(ValueError):
                self.prepare(controls=dict(self.controls, **updates))

    def test_native_descriptor_has_no_credentials_mutable_cache_or_ambiguous_ids(self):
        for updates in (dict(token='secret'), dict(items=['mutable cache']), dict(project_number=True),
                        dict(project_id='node\n'), dict(owner='../owner')):
            with self.assertRaises(ValueError):
                self.prepare(projects=dict(self.project, **updates))
        project = dict(self.project, status_options={name: 'duplicate' for name in self.project['status_options']})
        with self.assertRaises(ValueError):
            self.prepare(projects=project)
        report = self.prepare(projects=self.project)
        self.project['fields']['Progress'] = 'caller-change'
        self.assertNotIn('caller-change', report['arms']['github-projects']['initial_files'][RESOURCE_PATH])

    def test_instruction_change_during_inspection_refuses_mixed_prompt_bundle(self):
        from evaluation.preparation import read_regular
        seen = set()
        def change(path, limit, check):
            value = read_regular(path, limit, check)
            if path in seen:
                return value + b'Changed after initial snapshot'
            seen.add(path)
            return value
        with patch('evaluation.state_inputs.read_regular', side_effect=change):
            with self.assertRaises(ValueError):
                self.prepare()

    def test_controller_identity_includes_prompt_markdown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'evaluation/instructions').mkdir(parents=True)
            (root / 'pyproject.toml').write_text('fixture')
            (root / 'uv.lock').write_text('fixture')
            prompt = root / 'evaluation/instructions/state-common.md'; prompt.write_text('original')
            first = controller_identities(root)
            self.assertIn('evaluation/instructions/state-common.md', first)
            prompt.write_text('changed')
            self.assertNotEqual(first, controller_identities(root))


class ReviewedStateInputsTest(unittest.TestCase):
    def setUp(self):
        StateInputsTest.setUp(self)
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workload = self.root / 'workload'
        (self.workload / 'builder').mkdir(parents=True)
        (self.workload / 'review').mkdir()
        for name, content in self.files.items():
            path = self.workload / 'builder' / name
            path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(content)
        self.approval = self.workload / 'review/WORKLOAD-APPROVAL.json'
        self.approval.write_text(json.dumps(dict(schema_version=1,
            approval_type='workload_and_envelope_review_not_suite_freeze',
            workload_sha256={'builder/' + name: digest for name, digest in self.expected.items()})))
        self.control_path = self.root / 'controls.json'; self.control_path.write_text(json.dumps(self.controls))
        self.project_path = self.root / 'project.json'; self.project_path.write_text(json.dumps(self.project))
        (self.workload / 'review/protected-case.py').write_text('raise RuntimeError("never execute")')

    def prepare(self, **kwargs):
        return prepare_reviewed_state_inputs(self.workload, self.control_path, **kwargs)

    def test_reviewed_directory_excludes_operator_files_and_has_no_side_effects(self):
        before = {str(path): path.read_bytes() for path in self.root.rglob('*') if path.is_file()}
        with patch('subprocess.Popen', side_effect=AssertionError('No commands allowed')):
            report = self.prepare(projects_path=self.project_path)
        self.assertEqual(report['shared']['specification_files'], self.expected)
        self.assertEqual(report['operator_source_sha256']['workload_approval'],
                         hashlib.sha256(self.approval.read_bytes()).hexdigest())
        self.assertEqual(report['operator_source_sha256']['controls'],
                         hashlib.sha256(self.control_path.read_bytes()).hexdigest())
        self.assertNotIn('protected-case', json.dumps(report))
        self.assertFalse(report['boundary_review_verified'])
        self.assertEqual(before, {str(path): path.read_bytes() for path in self.root.rglob('*') if path.is_file()})

    def boundary_record(self):
        from evaluation.state_inputs import BOUNDARY_FILES
        repository = Path(__file__).resolve().parents[1]
        return dict(schema_version=1, approval_type='native_task_state_boundaries_not_suite_or_launch',
            reviewer='fixture human', recorded_utc='2026-10-07T22:00:00Z', launch_enabled=False,
            workload_approval_sha256=hashlib.sha256(self.approval.read_bytes()).hexdigest(),
            artifact_sha256={name: hashlib.sha256((repository/name).read_bytes()).hexdigest()
                             for name in BOUNDARY_FILES})

    def test_matching_boundary_approval_is_recorded_without_launch_authority(self):
        path = self.root/'boundary.json'; path.write_text(json.dumps(self.boundary_record()))
        report = self.prepare(boundary_approval_path=path)
        self.assertTrue(report['boundary_review_verified'])
        self.assertFalse(report['launch_enabled'])
        self.assertEqual(report['operator_source_sha256']['boundary_approval'],
                         hashlib.sha256(path.read_bytes()).hexdigest())

    def test_missing_stale_or_wrong_scope_boundary_review_refuses_inputs(self):
        path = self.root/'boundary.json'
        for change in ({'reviewer': ''}, {'schema_version': True}, {'launch_enabled': True},
                       {'approval_type': 'suite_approval'}, {'workload_approval_sha256': '0'*64},
                       {'artifact_sha256': {}}, {'recorded_utc': None}):
            with self.subTest(change=change):
                path.write_text(json.dumps(dict(self.boundary_record(), **change)))
                with self.assertRaises(ValueError): self.prepare(boundary_approval_path=path)
        record = self.boundary_record()
        record['artifact_sha256']['docs/task-state-workflows.md'] = '0'*64
        path.write_text(json.dumps(record))
        with self.assertRaises(ValueError): self.prepare(boundary_approval_path=path)

    def test_boundary_record_and_artifact_changes_during_preparation_are_rejected(self):
        from evaluation.preparation import read_regular
        path = self.root/'boundary.json'; path.write_text(json.dumps(self.boundary_record()))
        for changed in (path, Path(__file__).resolve().parents[1]/'docs/task-state-workflows.md'):
            seen = set()
            def changing_read(source, limit, check):
                content = read_regular(source, limit, check)
                if source == changed and source in seen:
                    return content + b'\n'
                seen.add(source)
                return content
            with self.subTest(changed=changed), patch('evaluation.state_inputs.read_regular', side_effect=changing_read):
                with self.assertRaises(ValueError): self.prepare(boundary_approval_path=path)

    def test_changed_reviewed_bytes_missing_files_and_extra_files_refuse_bundle(self):
        path = self.workload / 'builder/APPLICATION.md'; original = path.read_bytes()
        path.write_bytes(b'changed')
        with self.assertRaises(ValueError): self.prepare()
        path.unlink()
        with self.assertRaises(ValueError): self.prepare()
        path.write_bytes(original)
        (self.workload / 'builder/unreviewed.md').write_text('extra')
        with self.assertRaises(ValueError): self.prepare()

    def test_controls_or_approval_changed_during_inspection_are_rejected(self):
        from evaluation.state_inputs import prepare_state_inputs
        for path in (self.approval, self.control_path, self.project_path):
            original = path.read_bytes()
            def change(*args, **kwargs):
                value = prepare_state_inputs(*args, **kwargs)
                path.write_bytes(original + b'\n')
                return value
            with self.subTest(path=path), patch('evaluation.state_inputs.prepare_state_inputs', side_effect=change):
                with self.assertRaises(ValueError): self.prepare(projects_path=self.project_path)
            path.write_bytes(original)

    def test_duplicate_operator_keys_and_links_are_refused(self):
        self.control_path.write_text('{"model":"gpt-6-luna","model":"gpt-6-luna"}')
        with self.assertRaises(ValueError): self.prepare()
        self.control_path.unlink(); self.control_path.symlink_to(self.project_path)
        with self.assertRaises(OSError): self.prepare()

    def test_deadline_callback_can_abort_before_reviewed_input_reads(self):
        def expired(): raise TimeoutError('fixture expired')
        with self.assertRaises(TimeoutError): self.prepare(check=expired)

    def test_controller_command_records_bundle_and_failed_dirty_attempt(self):
        import sys
        from evaluation import __main__ as cli
        boundary = self.root/'boundary.json'; boundary.write_text(json.dumps(self.boundary_record()))
        def collect(attempt, label, argv, **kwargs):
            directory = attempt.directory / label; directory.mkdir()
            (directory / 'stdout.log').write_text('untracked-file' if dirty and label == 'worktree' else '')
            return dict(outcome='passed')
        for dirty in (False, True):
            with self.subTest(dirty=dirty), \
                    patch.object(cli, '__file__', str(self.root / 'evaluation/__main__.py')), \
                    patch.object(cli, 'collect', side_effect=collect), \
                    patch.object(sys, 'argv', ['evaluation', 'state-inputs', '--workload', str(self.workload),
                                            '--controls', str(self.control_path),
                                            '--boundary-approval', str(boundary)]):
                self.assertEqual(cli.main(), 2 if dirty else 0)
        results = [json.loads(path.read_text()) for path in
                   (self.root / '.factory-planning/state-input-review-logs').glob('run-*/result.json')]
        self.assertEqual({result['outcome'] for result in results},
                         {'state_inputs_prepared_for_review', 'inspection_error'})
        self.assertTrue(all(result['launch_enabled'] is False for result in results))
        prepared = next(result for result in results if result['outcome'] == 'state_inputs_prepared_for_review')
        self.assertTrue(prepared['boundary_review_verified'])
