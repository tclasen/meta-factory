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
