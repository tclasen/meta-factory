"""Real socket controls for private read-only audit observations."""
import json
import socket
import threading
import unittest
import uuid

from evaluation.audit_broker import AuditBroker, AuditObservationError, read_audit, send, receive
from evaluation.database_probe import AUDIT_FIELDS


class AuditBrokerTest(unittest.TestCase):
    def setUp(self):
        self.ids = [str(uuid.uuid4())]
        self.calls = []
        self.event = {key: None for key in AUDIT_FIELDS}
        self.event.update(id=str(uuid.uuid4()), action='auth.login', result='failure', correlation_id=self.ids[0])

    def reader(self, ids, canaries):
        self.calls.append((ids,canaries))
        return {'events':[self.event], 'truncated':False, 'connection_password':'parent-only'}

    def request(self, broker, value):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(2); connection.connect(str(broker.path))
            with connection.makefile('rwb') as stream:
                send(stream,value); return receive(stream)

    def test_only_projected_observation_crosses_real_socket(self):
        with AuditBroker(self.reader) as broker:
            result = read_audit(broker.configuration,self.ids,['private canary'])
            self.assertEqual(result,{'events':[self.event],'truncated':False})
            self.assertEqual(self.calls,[(self.ids,['private canary'])])
            self.assertEqual(broker.path.stat().st_mode & 0o777,0o600)
            self.assertEqual(broker.directory.stat().st_mode & 0o777,0o700)
        self.assertFalse(broker.directory.exists())

    def test_wrong_token_and_extra_command_fields_never_reach_reader(self):
        with AuditBroker(self.reader) as broker:
            original=dict(token=broker.token,correlations=self.ids,forbidden_values=[])
            for request in (dict(original,token='wrong'),dict(original,sql='DELETE FROM secrets')):
                self.assertEqual(self.request(broker,request),{'status':'refused'})
        self.assertEqual(self.calls,[])

    def test_invalid_payloads_are_refused_before_callback(self):
        with AuditBroker(self.reader) as broker:
            for ids,canaries in [(['not-a-uuid'],[]),(self.ids*2,[]),(self.ids,['']),
                                 (self.ids,['x'*4097]),(self.ids,[1])]:
                result=self.request(broker,dict(token=broker.token,correlations=ids,forbidden_values=canaries))
                self.assertEqual(result,{'status':'inconclusive'})
        self.assertEqual(self.calls,[])

    def test_duplicate_json_keys_never_reach_callback(self):
        with AuditBroker(self.reader) as broker:
            payload=json.dumps(dict(token=broker.token,correlations=self.ids,forbidden_values=[]))
            payload=payload[:-1]+',"correlations":[]}\n'
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
                connection.settimeout(2);connection.connect(str(broker.path));connection.sendall(payload.encode())
                self.assertEqual(connection.recv(1),b'')
            self.assertEqual(self.calls,[])
            self.assertEqual(read_audit(broker.configuration,self.ids)['events'],[self.event])

    def test_callback_exception_never_discloses_private_diagnostic(self):
        def broken(*args):raise RuntimeError('secret database credential')
        with AuditBroker(broken) as broker:
            response=self.request(broker,dict(token=broker.token,correlations=self.ids,forbidden_values=[]))
            self.assertEqual(response,{'status':'inconclusive'})

    def test_arbitrary_event_payload_and_nonboolean_flags_refused(self):
        invalid=[dict(self.event,password='private'),{'forbidden_text_present':1},
                 dict(self.event,action='x'*257)]
        for event in invalid:
            with self.subTest(event=list(event)), AuditBroker(lambda *_:{'events':[event],'truncated':False}) as broker:
                with self.assertRaises(AuditObservationError):read_audit(broker.configuration,self.ids)

    def test_redaction_and_truncation_are_preserved(self):
        result={'events':[{'forbidden_text_present':True},{'metadata_oversized':True}],'truncated':True}
        with AuditBroker(lambda *_:result) as broker:
            self.assertEqual(read_audit(broker.configuration,self.ids),result)

    def test_request_budget_cannot_be_reset_by_new_connection(self):
        with AuditBroker(self.reader,max_requests=1) as broker:
            read_audit(broker.configuration,self.ids)
            with self.assertRaises(AuditObservationError):read_audit(broker.configuration,self.ids)
        self.assertEqual(len(self.calls),1)

    def test_revocation_suppresses_inflight_response_and_reports_unfinished_reader(self):
        started=threading.Event();release=threading.Event();result=[]
        def reader(*args):
            started.set();release.wait(2)
            return {'events':[],'truncated':False}
        broker=AuditBroker(reader,cleanup_seconds=.05)
        def call():
            try:result.append(read_audit(broker.configuration,self.ids,timeout=2))
            except AuditObservationError:result.append('unavailable')
        thread=threading.Thread(target=call);thread.start()
        try:
            self.assertTrue(started.wait(1))
            with self.assertRaises(AuditObservationError):broker.close()
        finally:
            release.set();thread.join(3);broker.thread.join(3);broker.close()
        self.assertFalse(thread.is_alive())
        self.assertEqual(result,['unavailable'])
        self.assertFalse(broker.directory.exists())

    def test_oversized_callback_response_fails_without_partial_payload(self):
        # Each field meets its bound, but escaping expands the full wire payload.
        event={key:'"'*256 for key in AUDIT_FIELDS}
        with AuditBroker(lambda *_:{'events':[event]*128,'truncated':False}) as broker:
            with self.assertRaises(AuditObservationError):read_audit(broker.configuration,self.ids)


if __name__=='__main__':unittest.main()
