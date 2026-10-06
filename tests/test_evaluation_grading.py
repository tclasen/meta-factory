"""The evaluator must never turn absent/invalid grading into acceptance."""

import hashlib
from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import unittest

from evaluation.evidence import Attempt
from evaluation.fault_broker import FaultBroker
from evaluation.grading import Suite, run_suite


class GradingTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.suite = self.root / "suite"; self.suite.mkdir()
        self.packages = [{"id": "WP-001", "criteria": ["AC-001", "AC-002"]}]
        self.source = self.suite / "cases.py"
        self.source.write_text('def good(target):\n    assert target["value"] == 1, "wrong value"\n\ndef bad(target):\n    raise RuntimeError("fixture infrastructure")\n')
        self.manifest = {"schema_version": 1, "packages_sha256": hashlib.sha256(json.dumps(self.packages, sort_keys=True, separators=(",", ":")).encode()).hexdigest(), "files": {"cases.py": hashlib.sha256(self.source.read_bytes()).hexdigest()},
                         "cases": [{"id": "first", "source": "cases.py", "function": "good",
                                    "criteria": ["AC-001", "AC-002"], "timeout_seconds": 2}],
                         "coverage_complete": ["AC-001", "AC-002"]}
        self.save()

    def save(self):
        (self.suite / "suite.json").write_text(json.dumps(self.manifest))

    def approval(self):
        path = self.root / "review.json"
        path.write_text(json.dumps({"suite_sha256": hashlib.sha256((self.suite / "suite.json").read_bytes()).hexdigest(),
                                    "decision": "approved", "reviewer": "fixture reviewer", "reviewed_at": "fixture"}))
        return path

    def test_no_missing_or_unapproved_acceptance(self):
        suite = Suite(self.suite, self.packages)
        result = suite.aggregate({})
        self.assertFalse(result["project_success"])
        result = suite.aggregate({"first": {"case_id": "first", "verdict": "pass"}})
        self.assertEqual(result["accepted_packages"], [])
        self.assertEqual(result["development_passing_packages"], ["WP-001"])

    def test_incomplete_coverage_is_not_pass_or_approvable(self):
        self.manifest["coverage_complete"] = ["AC-001"]; self.save()
        suite = Suite(self.suite, self.packages)
        result = suite.aggregate({"first": {"case_id": "first", "verdict": "pass"}})
        self.assertEqual(result["criteria"]["AC-002"]["verdict"], "untested")
        with self.assertRaises(ValueError):
            Suite(self.suite, self.packages, approval=self.approval())

    def test_changed_source_and_stale_approval_refused(self):
        approval = self.approval()
        suite = Suite(self.suite, self.packages, approval=approval)
        self.source.write_text("changed")
        with self.assertRaises(ValueError): suite.verify()
        self.manifest["files"]["cases.py"] = hashlib.sha256(self.source.read_bytes()).hexdigest(); self.save()
        with self.assertRaises(ValueError): Suite(self.suite, self.packages, approval=approval)

    def test_unmapped_or_forged_result_refused(self):
        suite = Suite(self.suite, self.packages)
        with self.assertRaises(ValueError): suite.aggregate({"invented": {"verdict": "pass"}})
        with self.assertRaises(ValueError): suite.aggregate({"first": {"case_id": "other", "verdict": "pass"}})
        self.manifest["cases"][0]["criteria"] = ["AC-999"]; self.save()
        with self.assertRaises(ValueError): Suite(self.suite, self.packages)

    def test_worker_distinguishes_pass_failure_and_grader_error(self):
        for value, verdict in [(1, "pass"), (2, "fail")]:
            with Attempt(self.root / f"run-{value}", {}) as attempt:
                report = run_suite(attempt, Suite(self.suite, self.packages, approval=self.approval()),
                                   {"value": value}, deadline_seconds=5)
            self.assertEqual(report["criteria"]["AC-001"]["verdict"], verdict)
            self.assertEqual(report["project_success"], value == 1)
        self.manifest["cases"][0]["function"] = "bad"; self.save()
        with Attempt(self.root / "broken", {}) as attempt:
            report = run_suite(attempt, Suite(self.suite, self.packages), {}, deadline_seconds=5, development=True)
        self.assertEqual(report["criteria"]["AC-001"]["verdict"], "inconclusive")

    def test_selected_cases_cannot_accept_skipped_required_cases(self):
        self.manifest['cases'].append(dict(id='second', source='cases.py', function='good',
                                           criteria=['AC-002'], timeout_seconds=2))
        self.save()
        suite = Suite(self.suite, self.packages, approval=self.approval())
        with Attempt(self.root / 'selected', {}) as attempt:
            report = run_suite(attempt, suite, {'value':1}, deadline_seconds=5, case_ids=['first'])
        self.assertEqual(set(report['case_results']), {'first'})
        self.assertEqual(report['selected_case_ids'], ['first'])
        self.assertEqual(report['criteria']['AC-002']['cases'], ['first', 'second'])
        self.assertEqual(report['criteria']['AC-002']['verdict'], 'untested')
        self.assertFalse(report['project_success'])
        self.assertEqual(report['accepted_packages'], [])

    def test_selection_preserves_registry_order_and_shared_state_abort(self):
        self.manifest['cases'][0].update(mutates_shared_state=True)
        self.manifest['cases'].append(dict(id='second', source='cases.py', function='good',
                                           criteria=['AC-002'], timeout_seconds=2))
        self.save()
        with Attempt(self.root / 'selected-abort', {}) as attempt:
            report = run_suite(attempt, Suite(self.suite, self.packages), {'value':2},
                               deadline_seconds=5, development=True, case_ids=['second', 'first'])
        self.assertEqual(report['selected_case_ids'], ['first', 'second'])
        self.assertEqual(set(report['case_results']), {'first'})
        self.assertTrue(report['aborted'])

    def test_invalid_selection_refuses_before_target_or_worker_creation(self):
        suite = Suite(self.suite, self.packages)
        for index, selection in enumerate(([], ['unknown'], ['first', 'first'], 'first', [1], [{}], {'first'})):
            with self.subTest(selection=selection), Attempt(self.root / ('selection-' + str(index)), {}) as attempt:
                with self.assertRaises(ValueError):
                    run_suite(attempt, suite, {'value':1}, deadline_seconds=5,
                              development=True, case_ids=selection)
                self.assertFalse((attempt.directory / 'grading-target.json').exists())
                self.assertFalse((attempt.directory / 'grade-first').exists())

    def test_uncertain_runtime_fault_stops_following_cases(self):
        for mode in ('restore-error', 'timeout', 'exception'):
            source = {'restore-error': 'from evaluation.faults import FaultRestoreError\ndef first(target):\n    raise FaultRestoreError("fixture")\n',
                      'timeout': 'import time\ndef first(target):\n    time.sleep(10)\n',
                      'exception': 'def first(target):\n    raise RuntimeError("uncertain state")\n'}[mode]
            self.source.write_text(source + '\ndef second(target):\n    raise AssertionError("must not run")\n')
            self.manifest['files']['cases.py'] = hashlib.sha256(self.source.read_bytes()).hexdigest()
            self.manifest['cases'] = [dict(id='first', source='cases.py', function='first', criteria=['AC-001'],
                                           timeout_seconds=0.2 if mode == 'timeout' else 2, mutates_runtime=True),
                                      dict(id='second', source='cases.py', function='second', criteria=['AC-002'], timeout_seconds=2)]
            self.save()
            with Attempt(self.root / mode, {}) as attempt:
                report = run_suite(attempt, Suite(self.suite, self.packages), {}, deadline_seconds=5, development=True)
            self.assertTrue(report['aborted'])
            self.assertEqual(report['case_results']['first']['verdict'], 'inconclusive')
            self.assertNotIn('second', report['case_results'])
            self.assertEqual(report['criteria']['AC-002']['verdict'], 'untested')

    def test_broker_refusals_preserve_worker_verdict_and_sync_final_evidence(self):
        from types import SimpleNamespace
        modes = [
            ('fault', {'mutates_runtime': True}, {'fault_broker': SimpleNamespace(configuration={}, wait_idle=lambda: False, aborted=False)}),
            ('audit', {'reads_audit': True}, {'audit_broker': SimpleNamespace(configuration={}, wait_idle=lambda: False)}),
            ('job', {'reads_jobs': True}, {'job_broker': SimpleNamespace(configuration={}, wait_idle=lambda: False)}),
            ('staging', {'stages_jobs': True, 'mutates_runtime': True, 'reads_jobs': True},
             {'staging_broker': SimpleNamespace(configuration={}, wait_idle=lambda: False, aborted=False),
              'job_broker': SimpleNamespace(configuration={}, wait_idle=lambda: True)}),
            ('security', {'inspects_security': True}, {'security_broker': SimpleNamespace(configuration={}, wait_idle=lambda: False)}),
        ]
        for mode, declarations, brokers in modes:
            with self.subTest(mode=mode):
                self.manifest['cases'] = [dict(id='first', source='cases.py', function='good',
                    criteria=['AC-001'], timeout_seconds=2, **declarations),
                    dict(id='second', source='cases.py', function='good', criteria=['AC-002'], timeout_seconds=2)]
                self.save()
                with Attempt(self.root / ('retained-' + mode), {}) as attempt:
                    report = run_suite(attempt, Suite(self.suite, self.packages), {'value': 1},
                                       deadline_seconds=5, development=True, **brokers)
                    worker = json.loads((attempt.directory / 'grade-first' / 'worker-verdict.json').read_text())
                    final = json.loads((attempt.directory / 'first-verdict.json').read_text())
                    events = [json.loads(line) for line in (attempt.directory / 'events.jsonl').read_text().splitlines()]
                self.assertEqual(worker['verdict'], 'pass')
                self.assertEqual(final, report['case_results']['first'])
                self.assertEqual(final['verdict'], 'inconclusive')
                self.assertEqual([e['payload'] for e in events if e['type'] == 'case.result'], [final])
                self.assertTrue(report['aborted'])
                self.assertNotIn('second', report['case_results'])
                self.assertFalse(report['project_success'])

    def test_worker_preserves_explicit_missing_evidence_verdicts(self):
        for exception, verdict in [('Inconclusive', 'inconclusive'), ('Untested', 'untested')]:
            with self.subTest(exception=exception):
                self.source.write_text(
                    f'from evaluation.grade_worker import {exception}\n'
                    f'def good(target):\n    raise {exception}("Required fixture unavailable")\n')
                self.manifest['files']['cases.py'] = hashlib.sha256(self.source.read_bytes()).hexdigest()
                self.save()
                with Attempt(self.root / exception, {}) as attempt:
                    report = run_suite(attempt, Suite(self.suite, self.packages), {},
                                       deadline_seconds=5, development=True)
                self.assertEqual(report['case_results']['first']['verdict'], verdict)
                self.assertEqual(report['case_results']['first']['reason'], 'Required fixture unavailable')
                self.assertFalse(report['project_success'])

    def test_mutation_declaration_requires_boolean(self):
        for declaration in ('mutates_runtime', 'mutates_shared_state', 'reads_audit', 'reads_jobs', 'stages_jobs', 'inspects_security'):
            self.manifest['cases'][0][declaration] = 'false'; self.save()
            with self.assertRaises(ValueError): Suite(self.suite, self.packages)
            del self.manifest['cases'][0][declaration]

    def test_shared_fixture_failure_aborts_without_runtime_capability(self):
        for mode, body, verdict in [
                ('pass', 'pass', 'pass'),
                ('assertion', 'raise AssertionError("Membership changed unexpectedly")', 'fail'),
                ('inconclusive', 'raise Inconclusive("Restoration unknown")', 'inconclusive'),
                ('untested', 'raise Untested("Missing observation")', 'untested'),
                ('timeout', 'time.sleep(10)', 'inconclusive')]:
            self.source.write_text(
                'import time\nfrom evaluation.verdicts import Inconclusive, Untested\n'
                'def first(target):\n    assert "_fault_control" not in target\n    ' + body + '\n'
                'def second(target):\n    pass\n')
            self.manifest['files']['cases.py'] = hashlib.sha256(self.source.read_bytes()).hexdigest()
            self.manifest['cases'] = [dict(id='first', source='cases.py', function='first', criteria=['AC-001'],
                                           timeout_seconds=0.2 if mode == 'timeout' else 2, mutates_shared_state=True),
                                      dict(id='second', source='cases.py', function='second', criteria=['AC-002'], timeout_seconds=2)]
            self.save()
            @contextmanager
            def unexpected_fault(role):
                raise AssertionError('Shared state tests cannot request runtime faults')
                yield
            with FaultBroker(['storage'], unexpected_fault) as broker, Attempt(self.root / ('shared-' + mode), {}) as attempt:
                report = run_suite(attempt, Suite(self.suite, self.packages), {'_fault_control': {'untrusted': True}},
                                   deadline_seconds=5, development=True, fault_broker=broker)
            self.assertEqual(report['case_results']['first']['verdict'], verdict)
            self.assertEqual(report['aborted'], mode != 'pass')
            self.assertEqual('second' in report['case_results'], mode == 'pass')

    def test_security_grant_is_scoped_and_untrusted_target_configuration_removed(self):
        from evaluation.security_broker import SecurityBroker
        self.source.write_text('from evaluation.security_broker import read_security\n'
            'def first(target):\n'
            '    receipt=read_security(target["_security_control"],"password_storage")\n'
            '    assert receipt==dict(verdict="pass",reason="verified",observations_checked=2)\n'
            'def second(target):\n'
            '    assert "_security_control" not in target\n')
        self.manifest['files']['cases.py']=hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.manifest['cases']=[dict(id='first',source='cases.py',function='first',criteria=['AC-001'],timeout_seconds=2,inspects_security=True),
                               dict(id='second',source='cases.py',function='second',criteria=['AC-002'],timeout_seconds=2)]
        self.save()
        with SecurityBroker(lambda *_:dict(verdict='pass',reason='verified',observations_checked=2,raw_hash='private-must-not-cross')) as broker:
            with Attempt(self.root/'security',{}) as attempt:
                report=run_suite(attempt,Suite(self.suite,self.packages),{'_security_control':{'token':'forged'}},
                    deadline_seconds=5,development=True,security_broker=broker)
        self.assertEqual([r['verdict'] for r in report['case_results'].values()],['pass','pass'])
        self.assertEqual(json.loads((self.root/'security/grading-target.json').read_text()),{})
        for path in (self.root/'security').rglob('*'):
            if path.is_file():self.assertNotIn(b'private-must-not-cross',path.read_bytes())

    def test_missing_security_grant_cannot_self_pass_and_does_not_mutate_state(self):
        self.manifest['cases'][0]['inspects_security']=True
        self.manifest['cases'].append(dict(id='second',source='cases.py',function='good',criteria=['AC-002'],timeout_seconds=2))
        self.save()
        with Attempt(self.root/'missing-security',{}) as attempt:
            report=run_suite(attempt,Suite(self.suite,self.packages),{'value':1,'_security_control':{'token':'forged'}},
                deadline_seconds=5,development=True)
            self.assertFalse((attempt.directory/'grade-first').exists())
        self.assertEqual(report['case_results']['first']['reason'],'security_capability_unavailable')
        self.assertEqual(report['case_results']['first']['verdict'],'inconclusive')
        self.assertEqual(report['case_results']['second']['verdict'],'pass')
        self.assertFalse(report['aborted'])

    def test_unsettled_security_reader_suppresses_saved_pass_and_stops_later_cases(self):
        from types import SimpleNamespace
        self.manifest['cases'][0]['inspects_security']=True
        self.manifest['cases'].append(dict(id='second',source='cases.py',function='good',criteria=['AC-002'],timeout_seconds=2))
        self.save()
        with Attempt(self.root/'unsettled-security',{}) as attempt:
            report=run_suite(attempt,Suite(self.suite,self.packages),{'value':1},deadline_seconds=5,development=True,
                security_broker=SimpleNamespace(configuration={},wait_idle=lambda:False))
            saved=json.loads((attempt.directory/'first-verdict.json').read_text())
        self.assertTrue(report['aborted']);self.assertNotIn('second',report['case_results'])
        self.assertEqual(saved,report['case_results']['first'])
        self.assertEqual(saved['reason'],'security_reader_unsettled')

    def test_browser_cannot_receive_security_capability(self):
        self.manifest['cases'][0].update(browser='page',inspects_security=True);self.save()
        with self.assertRaisesRegex(ValueError,'host broker capabilities'):Suite(self.suite,self.packages)

    def test_worker_fault_requests_execute_in_parent_and_strip_untrusted_capability(self):
        self.source.write_text('from evaluation.fault_broker import remote_fault\ndef first(target):\n    with remote_fault(target["_fault_control"], "storage"):\n        pass\n\ndef second(target):\n    assert "_fault_control" not in target\n')
        self.manifest['files']['cases.py'] = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.manifest['cases'] = [dict(id='first', source='cases.py', function='first', criteria=['AC-001'], timeout_seconds=2, mutates_runtime=True),
                                  dict(id='second', source='cases.py', function='second', criteria=['AC-002'], timeout_seconds=2)]
        self.save(); events = []
        @contextmanager
        def factory(role):
            events.append(('suspend', role))
            try: yield
            finally: events.append(('restore', role))
        with FaultBroker(['storage'], factory) as broker, Attempt(self.root / 'broker', {}) as attempt:
            report = run_suite(attempt, Suite(self.suite, self.packages), {'_fault_control': {'token': 'untrusted'}},
                               deadline_seconds=5, development=True, fault_broker=broker)
        self.assertEqual(events, [('suspend', 'storage'), ('restore', 'storage')])
        self.assertEqual([v['verdict'] for v in report['case_results'].values()], ['pass', 'pass'])
        self.assertFalse(report['aborted'])

    def test_audit_capability_is_injected_only_for_declared_cases(self):
        from evaluation.audit_broker import AuditBroker
        self.source.write_text(
            'from evaluation.audit_broker import read_audit\n'
            'def first(target):\n'
            '    value = read_audit(target["_audit_control"], ["00000000-0000-0000-0000-000000000001"])\n'
            '    assert value == {"events": [], "truncated": False}\n'
            '    assert "_fault_control" in target\n'
            'def second(target):\n'
            '    assert "_audit_control" not in target\n'
            '    assert "_fault_control" not in target\n')
        self.manifest['files']['cases.py'] = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.manifest['cases'] = [dict(id='first', source='cases.py', function='first', criteria=['AC-001'],
                                       timeout_seconds=2, reads_audit=True, mutates_runtime=True),
                                  dict(id='second', source='cases.py', function='second', criteria=['AC-002'], timeout_seconds=2)]
        self.save()
        @contextmanager
        def fault(role): yield
        with AuditBroker(lambda *_: {'events': [], 'truncated': False}) as audit, FaultBroker(['storage'], fault) as faults:
            with Attempt(self.root / 'audit', {}) as attempt:
                report = run_suite(attempt, Suite(self.suite, self.packages),
                    {'_audit_control': {'token': 'forged'}, '_fault_control': {'token': 'forged'}},
                    deadline_seconds=5, development=True, audit_broker=audit, fault_broker=faults)
        self.assertEqual([v['verdict'] for v in report['case_results'].values()], ['pass', 'pass'])
        self.assertEqual(json.loads((self.root / 'audit/grading-target.json').read_text()), {})

    def test_unsettled_audit_reader_aborts_following_cases(self):
        from types import SimpleNamespace
        self.manifest['cases'][0]['reads_audit'] = True
        self.manifest['cases'].append(dict(id='second', source='cases.py', function='good',
                                          criteria=['AC-002'], timeout_seconds=2))
        self.save()
        with Attempt(self.root / 'unsettled-audit', {}) as attempt:
            report = run_suite(attempt, Suite(self.suite, self.packages), {'value': 1},
                deadline_seconds=5, development=True,
                audit_broker=SimpleNamespace(configuration={}, wait_idle=lambda: False))
        self.assertTrue(report['aborted'])
        self.assertEqual(report['case_results']['first']['reason'], 'audit_reader_unsettled')
        self.assertNotIn('second', report['case_results'])

    def test_job_capability_is_injected_only_for_declared_case(self):
        from evaluation.job_broker import JobBroker
        identity='00000000-0000-0000-0000-000000000001'
        self.source.write_text('from evaluation.job_broker import read_job\n'
            'def first(target):\n'
            '    value=read_job(target["_job_control"],"'+identity+'")\n'
            '    assert value["processing_attempts"] == 4\n'
            'def second(target):\n'
            '    assert "_job_control" not in target\n')
        self.manifest['files']['cases.py']=hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.manifest['cases']=[dict(id='first',source='cases.py',function='first',criteria=['AC-001'],timeout_seconds=2,reads_jobs=True),
                               dict(id='second',source='cases.py',function='second',criteria=['AC-002'],timeout_seconds=2)]
        self.save()
        value=dict(export_id=identity,status='running',processing_attempts=4,active_lease=True,
                   lease_fingerprint='a'*64,published_artifacts=0,completion_events=0)
        with JobBroker(lambda identity:value) as broker, Attempt(self.root/'jobs',{}) as attempt:
            result=run_suite(attempt,Suite(self.suite,self.packages),{'_job_control':{'token':'forged'}},
                             deadline_seconds=5,development=True,job_broker=broker)
        self.assertEqual([v['verdict'] for v in result['case_results'].values()],['pass','pass'])
        self.assertEqual(json.loads((self.root/'jobs/grading-target.json').read_text()),{})

    def test_unsettled_job_reader_aborts_later_cases(self):
        from types import SimpleNamespace
        self.manifest['cases'][0]['reads_jobs']=True
        self.manifest['cases'].append(dict(id='second',source='cases.py',function='good',criteria=['AC-002'],timeout_seconds=2))
        self.save()
        with Attempt(self.root/'unsettled-jobs',{}) as attempt:
            result=run_suite(attempt,Suite(self.suite,self.packages),{'value':1},deadline_seconds=5,development=True,
                             job_broker=SimpleNamespace(configuration={},wait_idle=lambda:False))
        self.assertTrue(result['aborted'])
        self.assertEqual(result['case_results']['first']['reason'],'job_reader_unsettled')
        self.assertNotIn('second',result['case_results'])

    def test_browser_cannot_request_job_capability(self):
        self.manifest['cases'][0].update(browser='page', reads_jobs=True)
        self.save()
        with self.assertRaisesRegex(ValueError, 'host broker capabilities'):
            Suite(self.suite, self.packages)

    def test_staging_requires_mutation_and_independent_job_declarations(self):
        for declaration in ('mutates_runtime', 'reads_jobs'):
            self.manifest['cases'][0].update(stages_jobs=True, mutates_runtime=True, reads_jobs=True)
            self.manifest['cases'][0][declaration]=False
            self.save()
            with self.assertRaisesRegex(ValueError, 'independent job observations'):
                Suite(self.suite, self.packages)

    def test_declared_staging_receives_only_staging_and_job_capabilities(self):
        from contextlib import contextmanager
        from types import SimpleNamespace
        from evaluation.staging_broker import StagingBroker, WORKER_RECEIPT, STORAGE_RECEIPT, RESTART_RECEIPT
        from evaluation.job_broker import JobBroker
        identity='00000000-0000-0000-0000-000000000001'
        self.source.write_text('from evaluation.staging_broker import remote_staging\n'
            'from evaluation.job_broker import read_job\n'
            'def first(target):\n'
            '    assert "_fault_control" not in target\n'
            '    with remote_staging(target["_staging_control"]) as stage:\n'
            '        stage.handoff()\n'
            '        assert read_job(target["_job_control"],"'+identity+'")["active_lease"]\n'
            '        stage.restart_worker()\n'
            'def second(target):\n'
            '    assert "_staging_control" not in target and "_job_control" not in target\n')
        self.manifest['files']['cases.py']=hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.manifest['cases']=[dict(id='first',source='cases.py',function='first',criteria=['AC-001'],timeout_seconds=2,
                                    mutates_runtime=True,reads_jobs=True,stages_jobs=True),
                               dict(id='second',source='cases.py',function='second',criteria=['AC-002'],timeout_seconds=2)]
        self.save();events=[]
        class Handle:
            observations={field:True for field in WORKER_RECEIPT}
            def handoff(self):return {field:True for field in STORAGE_RECEIPT}
            def restart_worker(self):return dict({field:True for field in RESTART_RECEIPT},restart_window={'earliest':0.0,'latest':0.0})
        @contextmanager
        def factory():
            events.append('held')
            try:yield Handle()
            finally:events.append('restored')
        def unrelated_wait():self.fail('General fault capability used during staged case')
        observation=dict(export_id=identity,status='running',processing_attempts=1,active_lease=True,
                         lease_fingerprint='a'*64,published_artifacts=0,completion_events=0)
        with StagingBroker(factory) as staging,JobBroker(lambda _:observation) as jobs,Attempt(self.root/'staging',{}) as attempt:
            result=run_suite(attempt,Suite(self.suite,self.packages),{'_staging_control':{'token':'forged'}},
                deadline_seconds=5,development=True,staging_broker=staging,job_broker=jobs,
                fault_broker=SimpleNamespace(configuration={},wait_idle=unrelated_wait,aborted=False))
        self.assertEqual([v['verdict'] for v in result['case_results'].values()],['pass','pass'])
        self.assertEqual(events,['held','restored'])
        self.assertEqual(json.loads((self.root/'staging/grading-target.json').read_text()),{})

    def test_missing_staging_or_job_capability_aborts_before_child_launch(self):
        from types import SimpleNamespace
        self.manifest['cases'][0].update(stages_jobs=True,mutates_runtime=True,reads_jobs=True)
        self.save()
        for index,capabilities in enumerate(({}, {'staging_broker':SimpleNamespace(configuration={},wait_idle=lambda:True,aborted=False)},
                                             {'job_broker':SimpleNamespace(configuration={},wait_idle=lambda:True)})):
            with Attempt(self.root/('staging-missing-'+str(index)),{}) as attempt:
                result=run_suite(attempt,Suite(self.suite,self.packages),{},deadline_seconds=2,development=True,**capabilities)
                self.assertFalse((attempt.directory/'grade-first').exists())
            self.assertTrue(result['aborted'])
            self.assertEqual(result['case_results']['first']['reason'],'staging_capability_unavailable')

    def test_unsettled_or_aborted_staging_prevents_later_cases(self):
        from types import SimpleNamespace
        self.manifest['cases'][0].update(stages_jobs=True,mutates_runtime=True,reads_jobs=True)
        self.manifest['cases'].append(dict(id='second',source='cases.py',function='good',criteria=['AC-002'],timeout_seconds=2))
        self.save()
        for index,(idle,aborted) in enumerate(((False,False),(True,True))):
            with Attempt(self.root/('staging-aborted-'+str(index)),{}) as attempt:
                result=run_suite(attempt,Suite(self.suite,self.packages),{'value':1},deadline_seconds=5,development=True,
                    job_broker=SimpleNamespace(configuration={},wait_idle=lambda:True),
                    staging_broker=SimpleNamespace(configuration={},wait_idle=lambda:idle,aborted=aborted))
            self.assertTrue(result['aborted'])
            self.assertNotIn('second',result['case_results'])
            self.assertEqual(result['case_results']['first']['reason'],'staging_control_aborted')

    def test_browser_staging_declaration_is_rejected(self):
        self.manifest['cases'][0].update(browser='page',stages_jobs=True,mutates_runtime=True,reads_jobs=True)
        self.save()
        with self.assertRaisesRegex(ValueError,'host broker capabilities'):Suite(self.suite,self.packages)
