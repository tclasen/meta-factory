"""Real subprocess transport tests: bounded stdin/output and secret-free evidence."""
import json
from pathlib import Path
import sys
import subprocess
from unittest.mock import patch
import tempfile
import unittest

from evaluation.database_transport import DatabaseTransport
from evaluation.evidence import Attempt
from evaluation.faults import FaultSetupError


class DatabaseTransportTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.attempt = Attempt(self.root / 'attempt', {})
        self.addCleanup(self.attempt.close)
        self.reserves = []

    def transport(self, code, **kwargs):
        return DatabaseTransport(self.attempt, [sys.executable, '-c', code],
            {'runtime': 'runtime_service', 'operator': 'operator_service'},
            check=self.reserves.append, cwd=self.root, **kwargs)

    def records(self):
        return [json.loads(p.read_text()) for p in self.attempt.directory.glob('database-*/result.json')]

    def test_sql_uses_stdin_and_raw_output_is_not_logged(self):
        marker = 'private-canary-do-not-log'
        transport = self.transport("import sys,json; print(json.dumps({'sql':sys.stdin.read(),'argv':sys.argv[1:]})); print('private-diagnostic-do-not-log',file=sys.stderr)")
        value = transport('runtime', "SELECT '" + marker + "';")
        self.assertIn(marker, value['sql'])
        self.assertIn('--no-password', value['argv'])
        self.assertIn('--file=-', value['argv'])
        self.assertIn('service=runtime_service', value['argv'])
        self.assertFalse(any(marker in arg for arg in value['argv']))
        self.assertEqual(self.reserves, [20, 5])
        for path in self.attempt.directory.rglob('*'):
            if path.is_file():
                self.assertNotIn(marker, path.read_text())
                self.assertNotIn('private-diagnostic-do-not-log', path.read_text())
        self.assertEqual(self.records()[0]['outcome'], 'observed')
        self.assertFalse(self.records()[0]['remote_termination_verified'])

    def test_operator_alias_is_fixed(self):
        value = self.transport("import sys,json; sys.stdin.read(); print(json.dumps({'args':sys.argv[1:]}))")('operator', 'SELECT 1;')
        self.assertIn('service=operator_service', value['args'])

    def test_unknown_identity_is_refused_before_execution(self):
        with self.assertRaises(ValueError):
            self.transport("raise Exception('must not execute')")('arbitrary', 'SELECT 1;')
        self.assertEqual(self.records(), [])

    def test_nonzero_exit_cannot_supply_a_successful_observation(self):
        with self.assertRaises(FaultSetupError):
            self.transport("import sys; sys.stdin.read(); print('{}'); sys.exit(7)")('runtime', 'SELECT 1;')
        record = self.records()[0]
        self.assertEqual(record['outcome'], 'command_failed')
        self.assertEqual(record['exit_code'], 7)

    def test_timeout_is_bounded_and_not_remote_termination_proof(self):
        with self.assertRaises(FaultSetupError):
            self.transport('import time; time.sleep(5)')('runtime', 'SELECT 1;', timeout=.1)
        record = self.records()[0]
        self.assertEqual(record['outcome'], 'timeout')
        self.assertLess(record['elapsed_seconds'], 2)
        self.assertFalse(record['remote_termination_verified'])

    def test_descendant_pipe_is_also_bounded_after_parent_exits(self):
        code = "import sys,subprocess; sys.stdin.read(); subprocess.Popen([sys.executable,'-c','import time; time.sleep(5)']); print('{}')"
        with self.assertRaises(FaultSetupError):
            self.transport(code)('runtime', 'SELECT 1;', timeout=.1)
        self.assertEqual(self.records()[0]['outcome'], 'timeout')

    def test_combined_output_limit_discards_raw_diagnostics(self):
        code = "import sys; sys.stdin.read(); print('{}'); sys.stderr.write('sensitive'*100)"
        with self.assertRaises(FaultSetupError):
            self.transport(code, max_output_bytes=128)('runtime', 'SELECT 1;')
        self.assertEqual(self.records()[0]['outcome'], 'output_limit')
        self.assertFalse(list(self.attempt.directory.rglob('stderr.log')))

    def test_invalid_json_shapes_and_duplicate_keys_are_refused(self):
        for data in ('not-json', '[]', '{} {}', '{"x":1,"x":2}', '{"x":NaN}'):
            with self.subTest(data=data), self.assertRaises(FaultSetupError):
                self.transport('import sys; sys.stdin.read(); print(' + repr(data) + ')')('runtime', 'SELECT 1;')
        self.assertTrue(all(r['outcome'] == 'invalid_observation' for r in self.records()))

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Requires Linux pipe-size control')
    def test_early_stdin_close_cannot_truncate_and_succeed(self):
        # Force partial delivery rather than assuming the host's pipe capacity.
        popen = subprocess.Popen
        def small_pipe(*args, **kwargs):
            return popen(*args, pipesize=4096, **kwargs)
        with patch('evaluation.database_transport.subprocess.Popen', side_effect=small_pipe):
            with self.assertRaises(FaultSetupError):
                self.transport("import os; os.close(0); print('{}')")('runtime', 'x' * 200000)
        self.assertNotEqual(self.records()[0]['outcome'], 'observed')

    def test_large_query_is_fully_delivered(self):
        value = self.transport("import sys,json; print(json.dumps({'length':len(sys.stdin.read())}))")('runtime', 'x' * 200000)
        self.assertEqual(value['length'], 200000)

    def test_expired_guard_after_command_refuses_observation(self):
        transport = self.transport("import sys; sys.stdin.read(); print('{}')")
        def check(reserve):
            self.reserves.append(reserve)
            if len(self.reserves) == 2:raise FaultSetupError('Expired')
        transport.check = check
        with self.assertRaises(FaultSetupError):transport('runtime', 'SELECT 1;')
        self.assertEqual(self.records()[0]['outcome'], 'transport_incomplete')

    def test_bounds_reject_unbounded_requests(self):
        transport = self.transport("raise Exception('must not execute')")
        for sql, timeout in (('', 1), ('x' * (256 * 1024 + 1), 1), ('SELECT 1;', 16)):
            with self.subTest(length=len(sql), timeout=timeout), self.assertRaises(ValueError):
                transport('runtime', sql, timeout=timeout)
        self.assertEqual(self.records(), [])
