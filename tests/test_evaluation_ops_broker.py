"""One-shot owned operation, strict request/result projection, and settlement."""
import copy
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest

from evaluation.evidence import Attempt,atomic_json
from evaluation.grading import Suite,run_suite,sha256
from evaluation.ops_broker import OpsBroker,project,receive,request_repeat_bootstrap,send
from evaluation.verdicts import Inconclusive


def result(verdict='pass'):
    return dict(outcome='repeat_bootstrap_incomplete' if verdict=='inconclusive' else 'repeat_bootstrap_checked',verdict=verdict,abort_suite=verdict!='pass')


class OpsBrokerTest(unittest.TestCase):
    def request(self,broker,value):
        connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);connection.settimeout(2)
        try:
            connection.connect(broker.configuration['socket'])
            with connection.makefile('rwb') as stream:send(stream,value);return receive(stream)
        finally:connection.close()
    def test_projection_drops_private_extra_fields(self):
        value=result();value['private']='private-credential'
        with OpsBroker(lambda:value) as broker:
            self.assertEqual(request_repeat_bootstrap(broker.configuration,timeout=2),dict(verdict='pass',abort_suite=False))
            self.assertTrue(broker.wait_idle());self.assertEqual(broker.result,dict(verdict='pass',abort_suite=False))
    def test_callback_failure_is_inconclusive_without_exception_content(self):
        def execute():raise RuntimeError('private-database-password')
        with OpsBroker(execute) as broker:
            value=request_repeat_bootstrap(broker.configuration,timeout=2)
            self.assertEqual(value,dict(verdict='inconclusive',abort_suite=True));self.assertNotIn('private-database-password',str(value))
    def test_wrong_token_never_executes(self):
        calls=[]
        with OpsBroker(lambda:calls.append(True)) as broker:
            response=self.request(broker,dict(token='wrong',operation='repeat-bootstrap'))
            self.assertEqual(response,dict(status='refused'));self.assertEqual(calls,[]);self.assertFalse(broker.used)
    def test_authenticated_command_injection_permanently_refuses(self):
        calls=[]
        with OpsBroker(lambda:calls.append(True)) as broker:
            response=self.request(broker,dict(token=broker.configuration['token'],operation='repeat-bootstrap',argv=['sh','private']))
            self.assertEqual(response,dict(status='inconclusive'));self.assertTrue(broker.used)
            with self.assertRaises(Inconclusive):request_repeat_bootstrap(broker.configuration,timeout=2)
            self.assertEqual(calls,[])
    def test_second_request_does_not_run_again_and_revokes_success(self):
        calls=[]
        def execute():calls.append(True);return result()
        with OpsBroker(execute) as broker:
            request_repeat_bootstrap(broker.configuration,timeout=2)
            with self.assertRaises(Inconclusive):request_repeat_bootstrap(broker.configuration,timeout=2)
            self.assertEqual(calls,[True]);self.assertEqual(broker.result,dict(verdict='inconclusive',abort_suite=True))
    def test_invalid_callback_result_cannot_report_pass(self):
        for value in (dict(result(),abort_suite=True),dict(result(),outcome='unknown'),dict(result(),verdict=True)):
            with OpsBroker(lambda:value) as broker:
                self.assertEqual(request_repeat_bootstrap(broker.configuration,timeout=2)['verdict'],'inconclusive')
    def test_unknown_operation_is_refused(self):
        calls=[]
        with OpsBroker(lambda:calls.append(True)) as broker:
            self.assertEqual(self.request(broker,dict(token=broker.configuration['token'],operation='destroy'))['status'],'inconclusive')
            self.assertEqual(calls,[])
    def test_unsettled_operation_is_not_cleanup_success(self):
        entered=threading.Event();release=threading.Event();errors=[]
        def execute():entered.set();release.wait(2);return result()
        broker=OpsBroker(execute,cleanup_seconds=.05)
        configuration=broker.configuration
        def request():
            try:request_repeat_bootstrap(configuration,timeout=2)
            except Exception as error:errors.append(type(error).__name__)
        thread=threading.Thread(target=request);thread.start()
        try:
            self.assertTrue(entered.wait(1));self.assertFalse(broker.wait_idle(.01))
            with self.assertRaises(RuntimeError):broker.close()
        finally:
            release.set();thread.join(2);broker.thread.join(2);broker.close()
        self.assertFalse(thread.is_alive());self.assertEqual(broker.result,dict(verdict='inconclusive',abort_suite=True));self.assertTrue(errors)
    def test_nonfinite_boolean_bounds_are_refused(self):
        for value in (True,0,float('nan'),float('inf')):
            with self.assertRaises(ValueError):OpsBroker(lambda:result(),request_seconds=value)
            with self.assertRaises(ValueError):request_repeat_bootstrap({},timeout=value)


class OpsGradingTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.suite=self.root/'suite';self.suite.mkdir()
        (self.suite/'case.py').write_text('from evaluation.ops_broker import request_repeat_bootstrap\ndef probe(target):\n request_repeat_bootstrap(target["_ops_control"],timeout=2)\ndef ignore(target):\n pass\ndef ordinary(target):\n assert "_ops_control" not in target\n')
        self.packages=[dict(id='WP',criteria=['AC'])]
        import hashlib
        self.base=dict(schema_version=1,packages_sha256=hashlib.sha256(json.dumps(self.packages,sort_keys=True,separators=(',',':')).encode()).hexdigest(),files={'case.py':sha256(self.suite/'case.py')},coverage_complete=['AC'])
    def make(self, function='probe', second=False, **changes):
        case=dict(id='repeat',source='case.py',function=function,criteria=['AC'],timeout_seconds=5,runs_ops=True,mutates_shared_state=True);case.update(changes)
        cases=[case]
        if second:cases.append(dict(id='ordinary',source='case.py',function='ordinary',criteria=['AC'],timeout_seconds=5))
        atomic_json(self.suite/'suite.json',dict(self.base,cases=cases));return Suite(self.suite,self.packages)
    def run_grade(self,suite,broker=None):
        with Attempt(self.root/'logs',{}) as attempt:
            value=run_suite(attempt,suite,dict(_ops_control={'token':'builder-supplied'}),deadline_seconds=10,development=True,ops_broker=broker)
        saved=json.loads((self.root/'logs/repeat-verdict.json').read_text());self.assertEqual(saved,value['case_results']['repeat'])
        self.assertFalse(value['project_success']);self.assertEqual(value['accepted_packages'],[])
        return value
    def test_owned_operation_passes_and_ordinary_worker_has_no_capability(self):
        with OpsBroker(lambda:result()) as broker:value=self.run_grade(self.make(second=True),broker)
        self.assertEqual(value['case_results']['repeat']['verdict'],'pass');self.assertIn('ordinary',value['case_results']);self.assertFalse(value['aborted'])
    def test_worker_pass_cannot_hide_parent_preservation_failure(self):
        with OpsBroker(lambda:result('fail')) as broker:value=self.run_grade(self.make(second=True),broker)
        self.assertEqual(value['case_results']['repeat']['verdict'],'fail');self.assertTrue(value['aborted']);self.assertNotIn('ordinary',value['case_results'])
        raw=json.loads((self.root/'logs/grade-repeat/worker-verdict.json').read_text());self.assertEqual(raw['verdict'],'pass')
    def test_worker_pass_cannot_hide_parent_inconclusive(self):
        with OpsBroker(lambda:result('inconclusive')) as broker:value=self.run_grade(self.make(second=True),broker)
        self.assertEqual(value['case_results']['repeat']['verdict'],'inconclusive');self.assertTrue(value['aborted'])
    def test_ignored_operation_cannot_pass(self):
        with OpsBroker(lambda:result()) as broker:value=self.run_grade(self.make(function='ignore'),broker)
        self.assertEqual(value['case_results']['repeat']['verdict'],'inconclusive');self.assertTrue(value['aborted'])
    def test_missing_capability_does_not_start_worker(self):
        value=self.run_grade(self.make())
        self.assertEqual(value['case_results']['repeat']['verdict'],'inconclusive');self.assertFalse((self.root/'logs/grade-repeat').exists())
    def test_reused_capability_cannot_pass_without_a_fresh_operation(self):
        with OpsBroker(lambda:result()) as broker:
            request_repeat_bootstrap(broker.configuration,timeout=2)
            value=self.run_grade(self.make(function='ignore'),broker)
        self.assertEqual(value['case_results']['repeat']['verdict'],'inconclusive')
    def test_operations_require_exclusive_shared_state_declaration(self):
        with self.assertRaises(ValueError):self.make(mutates_shared_state=False)
        with self.assertRaises(ValueError):self.make(reads_audit=True)
