"""Audit mutation uncertainty must not grant verification or permit unsafe cleanup."""
from contextlib import contextmanager
import json
from pathlib import Path
import re
import tempfile
import unittest

from evaluation.audit_faults import audit_insert_failure
from evaluation.evidence import Attempt
from evaluation.faults import FaultSetupError, FaultRestoreError


class AuditFaultTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.attempt = Attempt(Path(self.temp.name) / 'attempt', {})
        self.addCleanup(self.attempt.close)
        self.binding = dict(schema='public', table='audit_events', table_oid=123,
                            database_name='fixture', runtime_user='app', session_user='app',
                            operator_user='migration', operator_session_user='migration',
                            canary={'id': 'synthetic-id', 'message': 'private synthetic marker'})
        self.mode = 'good'
        self.calls = []
        self.checks = []
        self.installed = False

    def check(self, reserve):
        self.checks.append(reserve)
        if self.mode == 'guard-revoked' and self.installed:
            raise FaultSetupError('Guard revoked')

    def execute(self, identity, sql, *, timeout):
        self.assertEqual(timeout, 15)
        if 'ADD CONSTRAINT' in sql: phase = 'install'
        elif 'DROP CONSTRAINT' in sql: phase = 'restore'
        elif 'factory.audit_canary' in sql: phase = 'canary'
        else: phase = 'metadata'
        self.calls.append((phase, identity))
        role = 'app' if identity == 'runtime' else 'migration'
        common = {'current_user': role, 'session_user': role, 'database_name': 'fixture'}
        if phase == 'metadata':
            value = dict(common, relation_found=True, relation_oid='123', relation_kind='r')
            if self.mode == 'wrong-runtime' and identity == 'runtime':value['current_user'] = 'unexpected'
            if self.mode == 'wrong-operator-db' and identity == 'operator':value['database_name'] = 'other'
            return value
        if phase == 'install':
            self.assertTrue((self.attempt.directory / 'audit-state.json').exists())
            self.installed = True
            self.name = re.search(r'factory_audit_fault_[0-9a-f]{32}', sql)[0]
            if self.mode == 'lost-install-reply':raise OSError('private transport diagnostic')
            return {'outcome': 'audit_gate_installed', 'table_oid': '123',
                    'constraint_name': self.name, 'constraint_oid': True if self.mode == 'bad-oid' else '456'}
        if phase == 'restore':
            self.assertEqual(identity, 'operator')
            if self.mode == 'restore-fails':raise OSError('private transport diagnostic')
            self.installed = False
            return {'outcome': 'audit_gate_removed', 'table_oid': 123}
        if self.installed:
            result = dict(common, outcome='insert_rejected', sqlstate='23514',
                          constraint_name=self.name, schema='public', table='audit_events')
            if self.mode == 'wrong-constraint':result['constraint_name'] = 'unrelated'
            if self.mode == 'wrong-failure':result['sqlstate'] = '42501'
            return result
        recovery = ('restore', 'operator') in self.calls
        return dict(common, outcome='insert_executed', rows=0 if self.mode == 'no-baseline' or recovery and self.mode == 'recovery-fails' else 1)

    def fault(self):
        return audit_insert_failure(self.attempt, self.binding, execute=self.execute, check=self.check)

    def result(self):
        return json.loads((self.attempt.directory / 'audit-result.json').read_text())

    def test_successful_context_binds_identities_and_restores(self):
        with self.fault() as observation:
            self.assertEqual(observation, {'audit_insert_failure_verified': True})
            self.assertTrue(self.installed)
        self.assertFalse(self.installed)
        self.assertTrue(self.result()['restoration_verified'])
        self.assertEqual(self.checks[0], 210)
        self.assertEqual(self.calls, [('metadata', 'runtime'), ('canary', 'runtime'),
            ('metadata', 'operator'), ('install', 'operator'), ('canary', 'runtime'),
            ('restore', 'operator'), ('canary', 'runtime'), ('metadata', 'runtime')])
        for path in self.attempt.directory.iterdir():
            self.assertNotIn('private synthetic marker', path.read_text())

    def test_body_error_restores_before_propagation(self):
        with self.assertRaisesRegex(AssertionError, 'application failure'):
            with self.fault():raise AssertionError('application failure')
        self.assertTrue(self.result()['restoration_verified'])

    def test_interruption_restores(self):
        with self.assertRaises(KeyboardInterrupt):
            with self.fault():raise KeyboardInterrupt()
        self.assertTrue(self.result()['restoration_verified'])

    def test_wrong_runtime_never_installs(self):
        self.mode = 'wrong-runtime'
        with self.assertRaises(FaultSetupError):
            with self.fault():self.fail('Body ran')
        self.assertFalse(self.result()['mutation_attempted'])

    def test_wrong_operator_database_never_installs(self):
        self.mode = 'wrong-operator-db'
        with self.assertRaises(FaultSetupError):
            with self.fault():self.fail('Body ran')
        self.assertFalse(self.result()['mutation_attempted'])

    def test_unsuccessful_baseline_never_installs(self):
        self.mode = 'no-baseline'
        with self.assertRaises(FaultSetupError):
            with self.fault():self.fail('Body ran')
        self.assertFalse(self.result()['mutation_attempted'])

    def test_unrelated_constraint_failure_is_not_verified(self):
        self.mode = 'wrong-constraint'
        with self.assertRaises(FaultSetupError):
            with self.fault():self.fail('Body ran')
        self.assertTrue(self.result()['restoration_verified'])

    def test_other_sqlstate_is_not_verified(self):
        self.mode = 'wrong-failure'
        with self.assertRaises(FaultSetupError):
            with self.fault():self.fail('Body ran')
        self.assertTrue(self.result()['restoration_verified'])

    def test_lost_install_reply_requires_disposal_without_guessing(self):
        self.mode = 'lost-install-reply'
        with self.assertRaises(FaultRestoreError):
            with self.fault():self.fail('Body ran')
        self.assertTrue(self.installed)
        self.assertNotIn(('restore', 'operator'), self.calls)
        self.assertFalse(self.result()['restoration_verified'])

    def test_invalid_constraint_identity_does_not_authorize_drop(self):
        self.mode = 'bad-oid'
        with self.assertRaises(FaultRestoreError):
            with self.fault():self.fail('Body ran')
        self.assertNotIn(('restore', 'operator'), self.calls)

    def test_failed_removal_aborts(self):
        self.mode = 'restore-fails'
        with self.assertRaises(FaultRestoreError):
            with self.fault():pass
        self.assertFalse(self.result()['restoration_verified'])

    def test_missing_recovery_canary_aborts(self):
        self.mode = 'recovery-fails'
        with self.assertRaises(FaultRestoreError):
            with self.fault():pass
        self.assertFalse(self.result()['restoration_verified'])

    def test_revoked_guard_prevents_more_commands_and_aborts(self):
        self.mode = 'guard-revoked'
        with self.assertRaises(FaultRestoreError):
            with self.fault():self.fail('Body ran')
        self.assertEqual(self.calls[-1], ('install', 'operator'))
