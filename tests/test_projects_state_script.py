"""Projects preflight pagination and interruption retain reviewable evidence."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import test_projects_state as script


def page(identifier, *, more=False, cursor=None, fields_more=False):
    return {'node': {'items': {'pageInfo': {'hasNextPage': more, 'endCursor': cursor},
        'nodes': [dict(id=identifier, content=dict(title='Synthetic', body='Fixture'),
            fieldValues=dict(pageInfo={'hasNextPage': fields_more}, nodes=[
                dict(text='WP-001', field={'name': 'Work package'}),
                dict(name='Todo', optionId='option', field={'name': 'Status'})]))]}}}


class ProjectsScriptTest(unittest.TestCase):
    def test_native_pagination_keeps_all_items_and_checks_cursor(self):
        fixture = script.Fixture(None, 10)
        with patch.object(fixture, 'graphql', side_effect=[
                page('one', more=True, cursor='next'), page('two')]) as query:
            result = fixture.read_items('assigned-project')
        self.assertEqual(list(result), ['one', 'two'])
        self.assertEqual(result['one']['fields'], {'Work package': 'WP-001', 'Status': 'Todo'})
        self.assertEqual(query.call_args_list[1].args[2]['after'], 'next')

    def test_duplicate_items_truncated_fields_and_repeated_cursors_refuse_clean_result(self):
        cases = [[page('one', more=True, cursor='next'), page('one')],
                 [page('one', fields_more=True)],
                 [page('one', more=True)],
                 [page('one', more=True, cursor='next'), page('two', more=True, cursor='next')]]
        for pages in cases:
            fixture = script.Fixture(None, 10)
            with self.subTest(pages=pages), patch.object(fixture, 'graphql', side_effect=pages):
                with self.assertRaises(ValueError):
                    fixture.read_items('assigned-project')

    def run_script(self, execute, exercise=None):
        with tempfile.TemporaryDirectory() as directory:
            def command(unused, label, argv):
                return '' if label == 'worktree' else 'fixture-revision\n'
            with patch.object(script, 'ROOT', Path(directory)), \
                    patch.object(script.Fixture, 'command', command), \
                    patch.object(script, 'exercise', side_effect=exercise) as remote:
                status = script.main(['--owner', 'fixture-owner'] + (['--execute'] if execute else []))
                path, = (Path(directory) / '.factory-planning/projects-state-logs').glob('run-*/attempt/summary.json')
                report = json.loads(path.read_text())
                return status, report, remote.call_count

    def test_default_plan_never_calls_remote_exercise(self):
        status, report, count = self.run_script(False)
        self.assertEqual(status, 0)
        self.assertEqual(count, 0)
        self.assertEqual(report['outcome'], 'planned_not_executed')
        self.assertEqual(report['cleanup']['outcome'], 'no_resource_created')
        self.assertIn('started', report)
        self.assertIn('ended', report)
        self.assertEqual(report['tested_revision'], 'fixture-revision')

    def test_interrupted_creation_retains_title_for_cleanup_and_failure_status(self):
        def interrupt(fixture, owner, report):
            report['create_started'] = script.utc_now()
            raise KeyboardInterrupt()
        status, report, count = self.run_script(True, interrupt)
        self.assertEqual(status, 1)
        self.assertEqual(count, 1)
        self.assertEqual(report['exit_status'], 1)
        self.assertEqual(report['cleanup']['outcome'], 'creation_uncertain_find_by_unique_title')
        self.assertEqual(report['cleanup']['title'], report['project_title'])

    def test_failed_check_after_creation_retains_exact_owned_resource(self):
        def fail(fixture, owner, report):
            report.update(create_started=script.utc_now(), project=dict(id='owned-node', number=42),
                          cleanup=dict(outcome='retained_for_owner_review'))
            raise ValueError('private diagnostic must not reach summary')
        status, report, _ = self.run_script(True, fail)
        self.assertEqual(status, 1)
        self.assertEqual(report['project'], dict(id='owned-node', number=42))
        self.assertEqual(report['cleanup']['outcome'], 'retained_for_owner_review')
        self.assertNotIn('private diagnostic', json.dumps(report))
