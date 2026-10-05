"""The parent owns fault execution; worker disconnects cannot extend its authority."""

from contextlib import contextmanager
import os
import socket
import unittest

from evaluation.fault_broker import FaultBroker, remote_fault, send, receive
from evaluation.faults import FaultRestoreError, FaultSetupError


class BrokerTest(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.fail_restore = False

    @contextmanager
    def factory(self, role):
        self.events.append(('suspend', role))
        try:
            yield
        finally:
            self.events.append(('restore', role))
            if self.fail_restore:
                raise FaultRestoreError('fixture restoration failure')

    def test_roundtrip_and_permissions(self):
        with FaultBroker(['storage'], self.factory) as broker:
            self.assertEqual(os.stat(broker.path).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(broker.directory).st_mode & 0o777, 0o700)
            with remote_fault(broker.configuration, 'storage'):
                self.assertEqual(self.events, [('suspend', 'storage')])
            self.assertTrue(broker.wait_idle(2))
            self.assertEqual(self.events[-1], ('restore', 'storage'))
            self.assertFalse(broker.aborted)
        self.assertFalse(broker.path.exists())

    def test_body_assertion_restores_and_survives(self):
        with FaultBroker(['storage'], self.factory) as broker:
            with self.assertRaisesRegex(AssertionError, 'application failure'):
                with remote_fault(broker.configuration, 'storage'):
                    raise AssertionError('application failure')
            self.assertEqual(self.events[-1], ('restore', 'storage'))

    def test_wrong_capability_and_unknown_roles_cannot_execute(self):
        with FaultBroker(['storage'], self.factory) as broker:
            for configuration, role in [(dict(broker.configuration, token='wrong'), 'storage'),
                                         (broker.configuration, 'unrelated')]:
                with self.assertRaises(FaultSetupError):
                    with remote_fault(configuration, role): self.fail('Unexpected fault')
            self.assertEqual(self.events, [])

    def test_disconnect_restores_and_blocks_future_faults(self):
        with FaultBroker(['storage'], self.factory) as broker:
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.connect(str(broker.path))
            stream = connection.makefile('rwb')
            send(stream, dict(token=broker.token, operation='suspend', role='storage'))
            self.assertEqual(receive(stream)['status'], 'suspended')
            stream.close(); connection.close()
            self.assertTrue(broker.wait_idle(2))
            self.assertEqual(self.events[-1], ('restore', 'storage'))
            self.assertTrue(broker.aborted)
            with self.assertRaises(FaultRestoreError):
                with remote_fault(broker.configuration, 'storage'): pass
            self.assertEqual(len(self.events), 2)

    def test_restoration_failure_is_fatal_and_not_hidden_by_body_failure(self):
        self.fail_restore = True
        with FaultBroker(['storage'], self.factory) as broker:
            with self.assertRaises(FaultRestoreError):
                with remote_fault(broker.configuration, 'storage'):
                    raise AssertionError('original application failure')
            self.assertTrue(broker.aborted)

    def test_idle_client_cannot_hold_fault_indefinitely(self):
        with FaultBroker(['storage'], self.factory, idle_seconds=0.1) as broker:
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.connect(str(broker.path))
            with connection, connection.makefile('rwb') as stream:
                send(stream, dict(token=broker.token, operation='suspend', role='storage'))
                self.assertEqual(receive(stream)['status'], 'suspended')
                self.assertTrue(broker.wait_idle(2))
            self.assertEqual(self.events[-1], ('restore', 'storage'))
            self.assertTrue(broker.aborted)

    def test_parent_endpoint_loss_never_launches_a_replacement(self):
        with FaultBroker(['storage'], self.factory) as broker:
            configuration = broker.configuration
        with self.assertRaises(FaultSetupError):
            with remote_fault(configuration, 'storage'): pass
        self.assertEqual(self.events, [])

    def test_arbitrary_command_fields_are_refused(self):
        with FaultBroker(['storage'], self.factory) as broker:
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.connect(str(broker.path))
            with connection, connection.makefile('rwb') as stream:
                send(stream, dict(token=broker.token, operation='suspend', role='storage', command=['sh']))
                self.assertEqual(receive(stream)['status'], 'refused')
            self.assertEqual(self.events, [])

    def test_body_io_error_is_not_misreported_as_lost_control_connection(self):
        with FaultBroker(['storage'], self.factory) as broker:
            with self.assertRaisesRegex(OSError, 'body fixture'):
                with remote_fault(broker.configuration, 'storage'):
                    raise OSError('body fixture')
            self.assertEqual(self.events[-1], ('restore', 'storage'))
            self.assertFalse(broker.aborted)

    def test_service_observations_require_explicit_parent_boolean_and_are_projected(self):
        for evidence, expected in [(None, False), ({'service_outage_verified': 'true'}, False),
                                   ({'service_outage_verified': True, 'secret': 'do-not-forward'}, True)]:
            @contextmanager
            def factory(role):
                yield evidence
            with FaultBroker(['storage'], factory) as broker:
                with remote_fault(broker.configuration, 'storage') as observations:
                    self.assertEqual(observations, {'service_outage_verified': expected})

    def test_audit_fault_observation_excludes_database_capabilities_and_requires_true(self):
        for supplied in (True, False, 'true', 1, None):
            @contextmanager
            def factory(role):
                self.assertEqual(role, 'audit')
                yield {'audit_insert_failure_verified': supplied,
                       'connection': 'must-not-cross-broker', 'sql': 'must-not-cross-broker',
                       'table_oid': 1234, 'constraint_oid': 5678}
            with self.subTest(supplied=supplied), FaultBroker(['audit'], factory) as broker:
                with remote_fault(broker.configuration, 'audit') as observations:
                    self.assertEqual(observations, {'service_outage_verified': False,
                        'audit_insert_failure_verified': supplied is True})
                self.assertFalse(broker.aborted)

    def test_workload_receipt_requires_literal_true_and_excludes_identity_details(self):
        for supplied in (True, False, 'true', 1, None):
            @contextmanager
            def factory(role):
                yield {'workload_suspended_verified': supplied, 'uid': 'private-identity',
                       'pods': ['private-pod'], 'command': ['must-not-cross-broker']}
            with self.subTest(supplied=supplied), FaultBroker(['worker'], factory) as broker:
                with remote_fault(broker.configuration, 'worker') as observations:
                    self.assertEqual(observations, {'service_outage_verified': False,
                        'workload_suspended_verified': supplied is True})
                self.assertFalse(broker.aborted)
