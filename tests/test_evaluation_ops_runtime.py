"""Fresh operations capabilities cannot outlive their owner, case or deployment."""
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from evaluation.ops_runtime import OpsRuntime
from evaluation.ops_broker import request_repeat_bootstrap


class OpsRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.box=SimpleNamespace(name='factory-eval-grader-0123456789abcdef',project=self.root/'app',
            specification=self.root/'spec',creation_attempted=True,stopped=False)
        self.guard=SimpleNamespace(directory=self.root/'guard',process=Mock())
        self.guard.process.poll.return_value=None
        self.expected={'case':'private'}
        self.operation=Mock(return_value=dict(outcome='repeat_bootstrap_checked',verdict='pass',abort_suite=False))

    def runtime(self):
        runtime=OpsRuntime(self.root/'evidence',self.box,self.guard,observe=Mock(),verify=Mock(),
            expected_case=self.expected,source_check=lambda reserve:True,
            monotonic_deadline=time.monotonic()+300,wall_deadline=time.time()+300,operation=self.operation)
        self.addCleanup(runtime.close)
        return runtime

    def test_bound_operation_has_clipped_deadlines_and_separate_evidence(self):
        runtime=self.runtime();self.expected['case']='changed'
        runtime.broker.bind('repeat-bootstrap',timeout_seconds=20)
        self.assertEqual(request_repeat_bootstrap(runtime.broker.configuration)['verdict'],'pass')
        self.assertTrue(runtime.broker.wait_idle())
        options=self.operation.call_args.kwargs
        self.assertLessEqual(options['monotonic_deadline'],time.monotonic()+20)
        self.assertLessEqual(options['wall_deadline'],time.time()+20)
        self.assertEqual(options['expected_case'],{'case':'private'})
        child=list(runtime.directory.glob('repeat-*'))
        self.assertEqual(len(child),1)
        self.assertEqual(json.loads((child[0]/'result.json').read_text())['verdict'],'pass')

    def test_unbound_request_is_permanently_consumed(self):
        runtime=self.runtime()
        with self.assertRaises(Exception):request_repeat_bootstrap(runtime.broker.configuration)
        self.assertTrue(runtime.broker.used);self.operation.assert_not_called()

    def test_case_expiry_prevents_execution(self):
        runtime=self.runtime();runtime.broker.bind('repeat-bootstrap',timeout_seconds=20)
        runtime.case_deadlines=(time.monotonic()-1,time.time()-1)
        self.assertEqual(request_repeat_bootstrap(runtime.broker.configuration)['verdict'],'inconclusive')
        self.operation.assert_not_called()

    def test_guard_loss_after_operation_revokes_result_and_evidence(self):
        runtime=self.runtime();runtime.broker.bind('repeat-bootstrap',timeout_seconds=20)
        def operation(*args,**kwargs):
            self.box.stopped=True
            return dict(outcome='repeat_bootstrap_checked',verdict='pass',abort_suite=False)
        self.operation.side_effect=operation
        self.assertEqual(request_repeat_bootstrap(runtime.broker.configuration)['verdict'],'inconclusive')
        runtime.broker.wait_idle()
        child=next(runtime.directory.glob('repeat-*'))
        self.assertEqual(json.loads((child/'result.json').read_text())['verdict'],'inconclusive')

    def test_source_check_rechecks_lifetime(self):
        runtime=self.runtime()
        runtime.source_check=lambda reserve:setattr(self.box,'stopped',True) or True
        with self.assertRaises(Exception):runtime.checked_source(1)

    def test_expiry_between_receipt_and_parent_settlement_revokes_success(self):
        runtime=self.runtime();runtime.broker.bind('repeat-bootstrap',timeout_seconds=20)
        self.assertEqual(request_repeat_bootstrap(runtime.broker.configuration)['verdict'],'pass')
        runtime.broker.wait_idle()
        runtime.case_deadlines=(time.monotonic()-1,time.time()-1)
        self.assertEqual(runtime.broker.result,dict(verdict='inconclusive',abort_suite=True))
