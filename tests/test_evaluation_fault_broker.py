"""The parent owns fault execution; worker disconnects cannot extend its authority."""

from contextlib import contextmanager
import os
import socket
import unittest

from evaluation.fault_broker import FaultBroker, remote_fault, remote_fault_session, send, receive
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

    def test_audit_diagnostic_canary_requires_verified_audit_role(self):
        marker='factory_audit_fault_'+'a'*32
        for role, verified, included in [('audit',True,True),('audit',False,False),('audit',1,False),('storage',True,False)]:
            @contextmanager
            def factory(selected):
                yield dict(audit_insert_failure_verified=verified, audit_constraint_canary=marker, raw_exception='private SQL')
            with FaultBroker([role],factory) as broker:
                with remote_fault(broker.configuration,role) as observed:
                    self.assertEqual(observed.get('audit_constraint_canary'),marker if included else None)
                    self.assertNotIn('raw_exception',observed)

    def test_invalid_audit_diagnostic_canary_restores_and_refuses(self):
        for marker in ('private SQL',None,1,'factory_audit_fault_'+'A'*32,'factory_audit_fault_'+'a'*33):
            restored=[]
            @contextmanager
            def factory(role):
                try:yield dict(audit_insert_failure_verified=True,audit_constraint_canary=marker)
                finally:restored.append(True)
            with FaultBroker(['audit'],factory) as broker:
                with self.assertRaises(FaultSetupError):
                    with remote_fault(broker.configuration,'audit'):pass
                self.assertTrue(broker.wait_idle())
                self.assertEqual(restored,[True])

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

    def test_reviewed_restart_keeps_outer_fault_and_projects_only_receipts(self):
        def restart():
            self.assertEqual(self.events, [('suspend', 'storage')])
            self.events.append(('restart', 'worker'))
            return {'workload_restarted_verified': True, 'held_fault_verified': True,
                    'secret': 'not-forwarded', 'command': ['not-forwarded']}
        with FaultBroker(['storage', 'worker'], self.factory,
                         restart_actions={('storage', 'worker'): restart}) as broker:
            with remote_fault_session(broker.configuration, 'storage') as session:
                self.assertEqual(session.restart('worker'), {
                    'workload_restarted_verified': True, 'held_fault_verified': True})
                self.assertEqual(self.events[-1], ('restart', 'worker'))
                with self.assertRaises(FaultSetupError): session.restart('worker')
            self.assertEqual(self.events[-1], ('restore', 'storage'))
            self.assertFalse(broker.aborted)

    def test_unknown_restart_restores_held_fault_and_aborts(self):
        with FaultBroker(['storage', 'worker'], self.factory) as broker:
            with self.assertRaises(FaultRestoreError):
                with remote_fault_session(broker.configuration, 'storage') as session:
                    session.restart('worker')
            self.assertTrue(broker.wait_idle(2))
            self.assertEqual(self.events, [('suspend', 'storage'), ('restore', 'storage')])
            self.assertTrue(broker.aborted)

    def test_restart_requires_both_literal_verified_receipts(self):
        for supplied in (None, {}, {'workload_restarted_verified': True},
                         {'workload_restarted_verified': True, 'held_fault_verified': 'true'},
                         {'workload_restarted_verified': 1, 'held_fault_verified': True}):
            with self.subTest(supplied=supplied), FaultBroker(['storage', 'worker'], self.factory,
                    restart_actions={('storage', 'worker'): lambda: supplied}) as broker:
                with self.assertRaises(FaultRestoreError):
                    with remote_fault_session(broker.configuration, 'storage') as session:
                        session.restart('worker')
                self.assertTrue(broker.wait_idle(2))
                self.assertEqual(self.events[-1], ('restore', 'storage'))
                self.assertTrue(broker.aborted)

    def test_restart_callback_failure_restores_outer_context(self):
        def restart(): raise FaultRestoreError('Synthetic worker restoration failure')
        with FaultBroker(['storage', 'worker'], self.factory,
                         restart_actions={('storage', 'worker'): restart}) as broker:
            with self.assertRaises(FaultRestoreError):
                with remote_fault_session(broker.configuration, 'storage') as session:
                    session.restart('worker')
            self.assertTrue(broker.wait_idle(2))
            self.assertEqual(self.events[-1], ('restore', 'storage'))
            self.assertTrue(broker.aborted)

    def test_restart_mapping_rejects_unreviewed_or_same_role(self):
        for mapping in ({('storage','storage'):lambda: {}}, {('storage','other'):lambda: {}},
                        {('storage','worker'):None}, {'worker':lambda: {}}):
            with self.subTest(mapping=mapping), self.assertRaises(ValueError):
                FaultBroker(['storage','worker'],self.factory,restart_actions=mapping)

    def test_restart_client_rejects_integer_or_extra_receipts(self):
        import json
        from types import SimpleNamespace
        from evaluation.fault_broker import FaultSession
        cases=[({'workload_restarted_verified':True,'held_fault_verified':True},False),
               ({'workload_restarted_verified':1,'held_fault_verified':True},True),
               ({'workload_restarted_verified':True,'held_fault_verified':1},True),
               ({'workload_restarted_verified':True,'held_fault_verified':True,'extra':True},True),
               (None,True)]
        for observations,rejected in cases:
            with self.subTest(observations=observations):
                data=json.dumps({'status':'restarted','observations':observations}).encode()+b'\n'
                stream=SimpleNamespace(write=lambda value:len(value),flush=lambda:None,
                                       readline=lambda limit:data)
                session=FaultSession(stream,{})
                if rejected:
                    with self.assertRaises(FaultRestoreError):session.restart('worker')
                else:self.assertEqual(session.restart('worker'),observations)

    def test_ambiguous_or_nonfinite_json_is_rejected(self):
        import io
        for raw in (b'{"operation":"inspect","operation":"suspend"}\n',
                    b'{"observations":{"held_fault_verified":false,"held_fault_verified":true}}\n',
                    b'{"value":NaN}\n',b'{"value":Infinity}\n',b'{"value":-Infinity}\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):receive(io.BytesIO(raw))
        with self.assertRaises(ValueError):send(io.BytesIO(),{'value':float('nan')})

    def test_duplicate_operation_never_executes_callback(self):
        import json
        with FaultBroker(['storage'],self.factory) as broker:
            connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            connection.connect(str(broker.path))
            with connection,connection.makefile('rwb') as stream:
                raw=('{"token":'+json.dumps(broker.token)+',"role":"storage",'
                     '"operation":"inspect","operation":"suspend"}\n').encode()
                stream.write(raw);stream.flush()
                self.assertEqual(stream.readline(),b'')
            self.assertTrue(broker.wait_idle(2))
            self.assertEqual(self.events,[])
