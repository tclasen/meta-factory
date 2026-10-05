import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import uuid

from evaluation.audit_broker import AuditObservationError, read_audit
from evaluation.audit_runtime import AuditRuntime
from evaluation.database_probe import AUDIT_FIELDS


class AuditRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.box = SimpleNamespace(name='test-grader', stopped=False)
        self.guard = SimpleNamespace(directory=self.root / 'guard',
                                     process=SimpleNamespace(poll=lambda: None))
        self.guard.directory.mkdir()
        self.now = [100, 100]
        self.binding = dict(schema='public', table='audit', table_oid=123,
                            fields={k: {'column': k, 'path': []} for k in AUDIT_FIELDS},
                            database_name='fixture', operator_user='reader', operator_session_user='reader')
        self.value = dict(database_name='fixture', current_user='reader', session_user='reader',
                          relation_oid=123, events=[], truncated=False)
        self.calls = []
        self.peer_action = lambda _: None
        self.transport_action = lambda: None

    def runtime(self):
        def factory(attempt, prefix, services, *, check, cwd):
            def execute(identity, sql, *, timeout):
                check(timeout + 5)
                self.calls.append((attempt.directory, identity, sql, timeout))
                self.transport_action()
                return copy.deepcopy(self.value)
            return execute
        runtime = AuditRuntime(self.root / ('audit-' + uuid.uuid4().hex), self.box, self.guard,
            audit_binding=self.binding,
            database_peer={'prefix': ['trusted-peer'], 'services': {'runtime': 'app', 'operator': 'reader'}, 'cwd': self.root},
            database_peer_check=lambda allowance: self.peer_action(allowance),
            monotonic_deadline=200, wall_deadline=200,
            monotonic=lambda: self.now[0], wall=lambda: self.now[1], transport_factory=factory)
        self.addCleanup(runtime.close)
        return runtime

    def read(self, runtime):
        return read_audit(runtime.broker.configuration, [str(uuid.uuid4())], ['private-password-canary'])

    def test_private_requests_have_distinct_attempts_and_no_payload_evidence(self):
        runtime = self.runtime()
        self.binding['operator_user'] = 'changed-after-binding'
        self.assertEqual(self.read(runtime), {'events': [], 'truncated': False})
        self.read(runtime)
        self.assertNotEqual(self.calls[0][0], self.calls[1][0])
        self.assertEqual(self.calls[0][1], 'operator')
        self.assertIn('BEGIN READ ONLY', self.calls[0][2])
        for path in runtime.directory.rglob('*'):
            if path.is_file():
                self.assertNotIn('private-password-canary', path.read_text())
        self.assertEqual(json.loads((self.calls[0][0] / 'result.json').read_text())['outcome'], 'audit_observed')

    def test_database_and_relation_identity_mismatches_are_inconclusive(self):
        runtime = self.runtime()
        for key in ('database_name', 'current_user', 'session_user', 'relation_oid'):
            original = self.value[key]
            with self.subTest(key=key):
                self.value[key] = 'wrong'
                with self.assertRaises(AuditObservationError): self.read(runtime)
                self.value[key] = original

    def test_each_clock_and_guard_state_refuses_read_before_transport(self):
        runtime = self.runtime()
        for clock in range(2):
            self.now[clock] = 180
            with self.assertRaises(AuditObservationError): self.read(runtime)
            self.now[clock] = 100
        for name in ('release.json', 'result.json'):
            path = self.guard.directory / name
            path.touch()
            with self.assertRaises(AuditObservationError): self.read(runtime)
            path.unlink()
        self.box.stopped = True
        with self.assertRaises(AuditObservationError): self.read(runtime)
        self.box.stopped = False
        self.guard.process.poll = lambda: 0
        with self.assertRaises(AuditObservationError): self.read(runtime)
        self.assertEqual(self.calls, [])

    def test_peer_check_revocation_is_rechecked(self):
        runtime = self.runtime()
        self.peer_action = lambda _: runtime.revoked.set()
        with self.assertRaises(AuditObservationError): self.read(runtime)
        self.assertEqual(self.calls, [])

    def test_post_transport_revocation_suppresses_observation(self):
        runtime = self.runtime()
        self.transport_action = runtime.revoked.set
        with self.assertRaises(AuditObservationError): self.read(runtime)

    def test_peer_error_text_is_not_recorded(self):
        runtime = self.runtime()
        def fail(_): raise RuntimeError('private-password-canary')
        self.peer_action = fail
        with self.assertRaises(AuditObservationError): self.read(runtime)
        self.assertEqual(self.calls, [])

    def test_invalid_mapping_and_insufficient_lifetime_refused_at_construction(self):
        self.binding['fields'] = {}
        with self.assertRaises(ValueError): self.runtime()
        self.binding['fields'] = {k: {'column': k, 'path': []} for k in AUDIT_FIELDS}
        self.now[0] = 180
        with self.assertRaises(AuditObservationError): self.runtime()
