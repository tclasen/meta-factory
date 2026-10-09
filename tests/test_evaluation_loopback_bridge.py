"""Real direct HTTP and incomplete remote identity; no payload diagnostics."""
import http.server
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest

from evaluation.evidence import Attempt
from evaluation.loopback_bridge import LoopbackBridge
from evaluation.verdicts import Inconclusive


class LoopbackBridgeTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()

    def test_existing_http_publication_stays_direct_and_omits_private_headers(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_HEAD(self):
                self.send_response(403)
                self.send_header('X-Private','private-header-canary')
                self.end_headers()
            def log_message(self,*args):pass
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        self.addCleanup(server.shutdown)
        class Box:
            name='factory-eval-grader-0123456789abcdef'
            def exec_argv(self,args):raise AssertionError('Direct HTTP must not spawn VM commands')
        with Attempt(self.root/'direct',{}) as attempt:
            bridge=LoopbackBridge(attempt,Box(),host_port=server.server_port,
                lifetime_check=lambda reserve:True,monotonic_deadline=time.monotonic()+30,
                wall_deadline=time.time()+30)
            bridge.start();bridge.close()
            value=json.loads((attempt.directory/'loopback-bridge.json').read_text())
            self.assertEqual(value['mode'],'direct_http')
            self.assertEqual(value['status'],403)
            self.assertTrue(value['cleanup_verified'])
            self.assertFalse(value['resources_created'])
            self.assertNotIn('private-header-canary',json.dumps(value))

    def test_missing_lifetime_refuses_before_network_or_remote_commands(self):
        class Box:
            name='factory-eval-grader-0123456789abcdef'
            def exec_argv(self,args):raise AssertionError('Unavailable lifetime must not launch')
        def expired(reserve):raise Inconclusive('expired')
        with Attempt(self.root/'expired',{}) as attempt:
            bridge=LoopbackBridge(attempt,Box(),host_port=18080,lifetime_check=expired,
                monotonic_deadline=time.monotonic()+30,wall_deadline=time.time()+30)
            with self.assertRaises(Inconclusive):bridge.start()
            bridge.close()
            self.assertIsNone(bridge.process)

    def test_untrusted_readiness_cannot_authorize_pid_cleanup(self):
        import socket
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1',0));port=reserved.getsockname()[1]
        class Box:
            name='factory-eval-grader-0123456789abcdef'
            def exec_argv(self,args):
                if args[2].startswith('import json,os,signal'):
                    raise AssertionError('No unverified PID signal')
                source='import json,os,time; print(json.dumps(dict(outcome="owned_tcp_relay_ready",nonce="0"*32,pid=os.getpid(),uid=0,start_ticks="1",address="10.0.0.2",port=8080,upstream="127.0.0.1:8080")),flush=True); time.sleep(30)'
                return [sys.executable,'-c',source]
        with Attempt(self.root/'wrong-nonce',{}) as attempt:
            bridge=LoopbackBridge(attempt,Box(),host_port=port,lifetime_check=lambda reserve:True,
                monotonic_deadline=time.monotonic()+30,wall_deadline=time.time()+30)
            with self.assertRaises(ValueError):bridge.start()
            with self.assertRaises(Inconclusive):bridge.close()
            self.assertIsNotNone(bridge.process.poll())
            self.assertFalse(bridge.report['cleanup_verified'])


    def owned_peer(self, *, natural_exit=False, bad_receipt=False):
        import socket
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1',0));port=reservation.getsockname()[1]
        commands=[]
        peer = """import json,os,signal,sys,time
config=json.loads(sys.argv[1])
def done(*args):
 print(json.dumps(dict(outcome='owned_tcp_relay_stopped',nonce=('0'*32 if BAD else config['nonce']),counts=dict(connections=0,completed=0,errors=0,bytes=0,active=0))),flush=True)
 sys.exit(0)
signal.signal(signal.SIGTERM,done)
print(json.dumps(dict(outcome='owned_tcp_relay_ready',nonce=config['nonce'],pid=os.getpid(),uid=os.getuid(),start_ticks='1',address='10.0.0.2',port=8080,upstream='127.0.0.1:8080')),flush=True)
if NATURAL:
 time.sleep(.05);done()
while True:time.sleep(.1)
""".replace('BAD',repr(bad_receipt)).replace('NATURAL',repr(natural_exit))
        class Box:
            name='factory-eval-grader-0123456789abcdef'
            def exec_argv(self,args):
                if args[2].startswith('import json,os,signal'):
                    commands.append('stop')
                    # The synthetic local peer supplies the same bounded receipt
                    # contract. Native Linux process identity remains separate.
                    stop='import json,os,signal,sys; os.kill(json.loads(sys.argv[1])["pid"],signal.SIGTERM)'
                    return [sys.executable,'-c',stop,args[3]]
                commands.append('start')
                return [sys.executable,'-u','-c',peer,args[3]]
        return Box(),port,commands

    def test_exited_owned_peer_receipt_needs_no_expired_lifetime_or_pid_signal(self):
        box,port,commands=self.owned_peer(natural_exit=True)
        expired=[False]
        def check(reserve):
            if expired[0]:raise Inconclusive('grading expired')
            return True
        with Attempt(self.root/'exited',{}) as attempt:
            bridge=LoopbackBridge(attempt,box,host_port=port,lifetime_check=check,
                monotonic_deadline=time.monotonic()+30,wall_deadline=time.time()+30)
            bridge.start();bridge.process.wait(timeout=2);expired[0]=True;bridge.close()
            self.assertTrue(bridge.report['cleanup_verified'])
            self.assertEqual(commands,['start'])
            self.assertEqual(bridge.report['counts']['active'],0)

    def test_live_peer_cleanup_uses_separate_reserve_after_grading_expiry(self):
        box,port,commands=self.owned_peer();expired=[False];cleanup=[]
        def check(reserve):
            if expired[0]:raise Inconclusive('grading expired')
            return True
        def cleanup_check(reserve):cleanup.append(reserve);return True
        with Attempt(self.root/'cleanup-reserve',{}) as attempt:
            bridge=LoopbackBridge(attempt,box,host_port=port,lifetime_check=check,
                cleanup_lifetime_check=cleanup_check,monotonic_deadline=time.monotonic()+30,
                wall_deadline=time.time()+30)
            bridge.start();expired[0]=True;bridge.close()
            self.assertTrue(bridge.report['cleanup_verified'])
            self.assertEqual(cleanup,[12]);self.assertEqual(commands,['start','stop'])

    def test_exited_peer_with_wrong_stop_receipt_is_incomplete(self):
        box,port,commands=self.owned_peer(natural_exit=True,bad_receipt=True)
        with Attempt(self.root/'bad-stop-receipt',{}) as attempt:
            bridge=LoopbackBridge(attempt,box,host_port=port,lifetime_check=lambda reserve:True,
                monotonic_deadline=time.monotonic()+30,wall_deadline=time.time()+30)
            bridge.start();bridge.process.wait(timeout=2)
            with self.assertRaises(Inconclusive):bridge.close()
            self.assertFalse(bridge.report['cleanup_verified'])
            self.assertEqual(commands,['start'])


    def test_false_cleanup_permission_never_sends_remote_stop(self):
        box,port,commands=self.owned_peer()
        with Attempt(self.root/'false-cleanup-check',{}) as attempt:
            bridge=LoopbackBridge(attempt,box,host_port=port,lifetime_check=lambda reserve:True,
                cleanup_lifetime_check=lambda reserve:False,monotonic_deadline=time.monotonic()+30,
                wall_deadline=time.time()+30)
            bridge.start()
            with self.assertRaises(Inconclusive):bridge.close()
            self.assertFalse(bridge.report['cleanup_verified'])
            self.assertEqual(commands,['start'])
            self.assertIsNotNone(bridge.process.poll())
