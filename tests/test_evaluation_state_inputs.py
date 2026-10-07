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
