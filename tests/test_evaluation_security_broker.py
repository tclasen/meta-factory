"""Security scope stays parent-side; raw callback/request data never becomes evidence."""
import socket
import threading
import unittest

from evaluation.audit_broker import receive,send
from evaluation.security_broker import SecurityBroker,SecurityObservationError,project,read_security


CANARY='Private-security-fixture-canary'
PASS=dict(verdict='pass',reason='verified',observations_checked=2)


class SecurityBrokerTest(unittest.TestCase):
    def test_password_request_has_no_scope_and_strips_callback_secrets(self):
        seen=[]
        def reader(operation,canaries):
            seen.append((operation,canaries));return dict(PASS,raw_hash=CANARY,raw_rows=[CANARY])
        with SecurityBroker(reader) as broker:
            result=read_security(broker.configuration,'password_storage')
            self.assertEqual(result,PASS)
            self.assertEqual(seen,[('password_storage',None)])
            self.assertNotIn(CANARY,repr(result))
            path=broker.directory
        self.assertFalse(path.exists())

    def test_log_canaries_are_private_and_source_selection_is_absent(self):
        seen=[]
        def reader(operation,canaries):
            seen.append((operation,canaries));return dict(verdict='fail',reason='canary_present',observations_checked=1,raw_logs=CANARY)
        with SecurityBroker(reader) as broker:
            result=read_security(broker.configuration,'log_canaries',canaries=[CANARY])
            self.assertEqual(result,dict(verdict='fail',reason='canary_present',observations_checked=1))
            self.assertEqual(seen,[('log_canaries',[CANARY])])
            self.assertNotIn(CANARY,repr(result))

    def test_callback_exception_and_unapproved_reason_are_unavailable(self):
        def failed(*_):raise AssertionError(CANARY)
        for reader in (failed,lambda *_:dict(PASS,reason=CANARY),lambda *_:dict(PASS,observations_checked=True)):
            with SecurityBroker(reader) as broker:
                with self.assertRaisesRegex(SecurityObservationError,'^Security inspection unavailable$'):
                    read_security(broker.configuration,'password_storage')

    def test_parent_can_report_inconclusive_without_grader_failure_text(self):
        receipt=dict(verdict='inconclusive',reason='unavailable',observations_checked=0)
        with SecurityBroker(lambda *_:receipt) as broker:
            self.assertEqual(read_security(broker.configuration,'password_storage'),receipt)

    def test_worker_scope_injection_and_wrong_token_never_invoke_reader(self):
        seen=[]
        with SecurityBroker(lambda *args:seen.append(args)) as broker:
            for extra in (dict(accounts=['private']),dict(profile='builder-selected'),dict(canaries=[CANARY]),dict(token='wrong')):
                request=dict(token=broker.token,operation='password_storage');request.update(extra)
                connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);connection.settimeout(2)
                with connection:
                    connection.connect(str(broker.path))
                    with connection.makefile('rwb') as stream:
                        send(stream,request);self.assertEqual(receive(stream),{'status':'refused'})
            self.assertEqual(seen,[])

    def test_request_budget_prevents_extra_inspection(self):
        seen=[]
        with SecurityBroker(lambda *args:seen.append(args) or PASS,max_requests=1) as broker:
            self.assertEqual(read_security(broker.configuration,'password_storage'),PASS)
            with self.assertRaises(SecurityObservationError):read_security(broker.configuration,'password_storage')
        self.assertEqual(len(seen),1)

    def test_close_revokes_blocked_reader_and_removes_socket(self):
        entered=threading.Event();release=threading.Event();results=[]
        def reader(*_):entered.set();release.wait(2);return PASS
        broker=SecurityBroker(reader,cleanup_seconds=3)
        def request():
            try:read_security(broker.configuration,'password_storage')
            except SecurityObservationError:results.append('unavailable')
        client=threading.Thread(target=request);client.start();self.assertTrue(entered.wait(1))
        closer=threading.Thread(target=broker.close);closer.start();self.assertTrue(broker.closing.wait(1));release.set()
        closer.join(2);client.join(2)
        self.assertFalse(closer.is_alive());self.assertFalse(client.is_alive())
        self.assertEqual(results,['unavailable']);self.assertFalse(broker.directory.exists())

    def test_static_receipt_domains_and_wire_extras_refused(self):
        for operation,value in [('password_storage',dict(PASS,observations_checked=1)),('log_canaries',dict(PASS,observations_checked=0)),
                                ('password_storage',dict(verdict='fail',reason='reused_salt',observations_checked=1)),
                                ('log_canaries',dict(verdict='fail',reason='plaintext',observations_checked=1)),
                                ('password_storage',dict(PASS,observations_checked=65)),('log_canaries',dict(PASS,observations_checked=129)),
                                ('password_storage',dict(PASS,reason={})),('password_storage',dict(PASS,verdict=[]))]:
            with self.assertRaises(ValueError):project(operation,value)
        with self.assertRaises(ValueError):project('password_storage',dict(PASS,private=CANARY),wire=True)

    def test_nonfinite_or_boolean_broker_time_bounds_refused(self):
        for kwargs in ({'request_seconds':True},{'request_seconds':float('nan')},{'cleanup_seconds':True},{'cleanup_seconds':float('inf')}):
            with self.assertRaises(ValueError):SecurityBroker(lambda *_:PASS,**kwargs)

    def test_invalid_worker_requests_refused_before_connection(self):
        for operation,canaries,timeout in [('commands',None,1),('password_storage',[CANARY],1),('log_canaries',[],1),
                                           ('log_canaries',['short'],1),('password_storage',None,True),('password_storage',None,61)]:
            with self.assertRaises(ValueError):read_security({},operation,canaries=canaries,timeout=timeout)


if __name__=='__main__':unittest.main()
