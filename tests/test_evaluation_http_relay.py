"""Real HTTP/Unix transport must preserve app traffic without becoming a proxy."""
import contextlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from evaluation.http_relay import RelayServer


class App(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *args): pass
    def do_GET(self): self.reply()
    def do_POST(self): self.reply()
    def do_HEAD(self): self.reply()
    def reply(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        self.server.requests.append((self.command, self.path, list(self.headers.items()), body))
        if self.path == '/slow':
            self.server.started.set()
            self.server.release.wait(2)
        if self.path == '/chunked':
            self.send_response(200); self.send_header('Transfer-Encoding', 'chunked'); self.end_headers()
            self.wfile.write(b'3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n'); return
        payload = body if self.command == 'POST' else b'fixed application bytes'
        self.send_response(302 if self.path == '/redirect' else 200)
        if self.path == '/redirect': self.send_header('Location', 'http://unavailable.invalid/private')
        self.send_header('Set-Cookie', 'first=one; Path=/'); self.send_header('Set-Cookie', 'second=two; Path=/')
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(len(payload)))
        if self.path == '/ambiguous': self.send_header('Content-Length', str(len(payload) + 1))
        self.end_headers()
        if self.command != 'HEAD':
            with contextlib.suppress(OSError): self.wfile.write(payload)


class RelayTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='relay-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.app = ThreadingHTTPServer(('127.0.0.1', 0), App)
        self.app.requests = []; self.app.release = threading.Event(); self.app.started = threading.Event()
        self.app.handle_error = lambda *_: None
        self.serve(self.app)
        self.authority = '127.0.0.1:18080'
        self.peer = dict(kind='tcp', host='127.0.0.1', port=self.app.server_port)

    def serve(self, server):
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        thread.start()
        def cleanup():
            self.app.release.set()
            server.shutdown(); server.server_close(); thread.join(2)
            self.assertFalse(thread.is_alive())
        self.addCleanup(cleanup)
        return server

    def relay(self, **options):
        return self.serve(RelayServer(('127.0.0.1', 0), self.peer, self.authority, **options))

    def request(self, relay, method='GET', path='/', body=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', relay.server_port, timeout=2)
        try:
            connection.request(method, path, body=body, headers={'Host':self.authority, **(headers or {})})
            response = connection.getresponse()
            return response.status, response.getheaders(), response.read()
        finally: connection.close()

    def raw(self, relay, message):
        with socket.create_connection(('127.0.0.1', relay.server_port), timeout=2) as connection:
            connection.sendall(message)
            result = bytearray()
            while True:
                data = connection.recv(65536)
                if not data: return bytes(result)
                result.extend(data)

    def test_browser_loopback_through_private_socket_preserves_bytes_and_cookies(self):
        path = str(Path(self.temp.name) / 'app.sock')
        peer = self.serve(RelayServer(path, self.peer, self.authority))
        relay = self.serve(RelayServer(('127.0.0.1', 0), dict(kind='unix', path=path), self.authority))
        self.assertEqual(Path(path).stat().st_mode & 0o777, 0o600)
        payload = b'multipart-like\x00\xff\r\n' * 10000
        status, headers, body = self.request(relay, 'POST', '/api/files?value=%2F', payload,
                                           {'Cookie':'synthetic-private-cookie', 'Origin':'http://' + self.authority})
        self.assertEqual((status, body), (200, payload))
        self.assertEqual(len([v for k,v in headers if k.lower() == 'set-cookie']), 2)
        request = self.app.requests[-1]
        self.assertEqual(request[1], '/api/files?value=%2F')
        self.assertIn(('Host', self.authority), request[2])
        self.assertIn(('Cookie', 'synthetic-private-cookie'), request[2])
        self.assertNotIn('synthetic-private-cookie', json.dumps(peer.observation()))

    def test_chunked_upload_is_bounded_and_normalized(self):
        relay = self.relay()
        response = self.raw(relay, b'POST /api/files HTTP/1.1\r\nHost: '+self.authority.encode()+
            b'\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n')
        self.assertIn(b'200 OK', response)
        self.assertTrue(response.endswith(b'onetwo'))
        self.assertEqual(self.app.requests[-1][3], b'onetwo')

    def test_chunked_response_and_head(self):
        relay = self.relay()
        self.assertEqual(self.request(relay, path='/chunked')[2], b'onetwo')
        self.assertEqual(self.request(relay, method='HEAD')[2], b'')

    def test_redirect_is_returned_without_following_it(self):
        status, headers, _ = self.request(self.relay(), path='/redirect')
        self.assertEqual(status, 302)
        self.assertIn(('Location', 'http://unavailable.invalid/private'), headers)
        self.assertEqual(len(self.app.requests), 1)

    def test_arbitrary_targets_host_and_upgrade_are_refused(self):
        relay = self.relay()
        for method, path, headers in [('GET','http://unavailable.invalid/',{}), ('CONNECT','127.0.0.1:22',{}),
                ('GET','//unavailable.invalid/',{}), ('GET','/',{'Host':'unavailable.invalid'}),
                ('GET','/',{'Upgrade':'websocket'}), ('GET','/',{'Expect':'100-continue'})]:
            with self.subTest(method=method,path=path,headers=list(headers)):
                status, _, body = self.request(relay, method, path, headers=headers)
                self.assertIn(status, (400,417))
                self.assertEqual(body, b'{"error":"relay_unavailable"}')
        self.assertEqual(self.app.requests, [])

    def test_ambiguous_framing_never_reaches_application(self):
        relay = self.relay()
        for extra in (b'Content-Length: 0\r\nContent-Length: 1\r\n',
                      b'Content-Length: 0\r\nTransfer-Encoding: chunked\r\n',
                      b'Host: second.invalid\r\n', b'Content-Length: -1\r\n'):
            reply = self.raw(relay, b'POST / HTTP/1.1\r\nHost: '+self.authority.encode()+b'\r\n'+extra+b'\r\n')
            self.assertIn(b'400 Bad Request', reply)
        self.assertEqual(self.app.requests, [])

    def test_input_output_and_response_framing_limits(self):
        relay = self.relay(max_request_bytes=4, max_response_bytes=8)
        self.assertEqual(self.request(relay, 'POST', body=b'12345')[0], 413)
        self.assertEqual(self.request(relay)[0], 502)
        self.assertEqual(relay.observation()['request_limit'], 1)
        self.assertEqual(relay.observation()['response_limit'], 1)
        self.assertEqual(self.request(self.relay(), path='/ambiguous')[0], 502)

    def test_deadline_interrupts_upstream_wait_and_slow_client(self):
        relay = self.relay(request_seconds=.15)
        started = time.monotonic()
        try:
            self.assertEqual(self.request(relay, path='/slow')[0], 502)
        except (http.client.RemoteDisconnected, http.client.IncompleteRead, ConnectionResetError):
            pass
        self.assertLess(time.monotonic() - started, 1)
        with socket.create_connection(('127.0.0.1', relay.server_port), timeout=1) as connection:
            connection.sendall(b'GET / HTTP/1.1\r\nHost: ')
            time.sleep(.25)
            self.assertEqual(connection.recv(4096), b'')
        self.assertGreaterEqual(relay.observation().get('deadline', 0), 1)

    def test_guard_failure_and_exception_text_are_not_exposed(self):
        def unavailable(): raise RuntimeError('private-credential-canary')
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            relay = self.relay(check=unavailable)
            status, _, body = self.request(relay)
        self.assertEqual(status, 502)
        self.assertNotIn(b'private-credential-canary', body)
        self.assertNotIn('private-credential-canary', stderr.getvalue())
        self.assertEqual(self.app.requests, [])

    def test_socket_timeout_is_recorded_when_timer_never_runs(self):
        relay = self.relay(request_seconds=.05)
        # Deterministically model a timer thread that loses the scheduling race
        # to the parser's socket timeout, then is cancelled by handler cleanup.
        with patch('evaluation.http_relay.threading.Timer'):
            with socket.create_connection(('127.0.0.1', relay.server_port), timeout=1) as connection:
                connection.sendall(b'GET / HTTP/1.1\r\nHost: ')
                self.assertEqual(connection.recv(4096), b'')
            self.assertEqual(relay.observation().get('deadline'), 1)
        self.assertEqual(self.app.requests, [])

    def test_listener_and_peer_configuration_is_operator_owned(self):
        for address, peer in [(('0.0.0.0', 0), self.peer), (('127.0.0.1', 0),dict(kind='tcp',host='example.com',port=80)),
                              (('127.0.0.1', 0),dict(kind='unix',path='relative.sock'))]:
            with self.assertRaises(ValueError): RelayServer(address, peer, self.authority)

    def test_shutdown_revokes_an_active_upstream_request(self):
        relay = self.relay(request_seconds=2)
        result = []
        def client():
            try: result.append(self.request(relay, path='/slow')[0])
            except (http.client.RemoteDisconnected, ConnectionResetError): result.append('closed')
        thread = threading.Thread(target=client); thread.start()
        self.assertTrue(self.app.started.wait(1))
        started = time.monotonic()
        relay.shutdown(); relay.server_close()
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertLess(time.monotonic() - started, 1)
        self.assertIn(result[0], (502, 'closed'))
        self.assertEqual(relay.handlers, set())

    def test_failed_socket_bind_does_not_remove_existing_file(self):
        path = Path(self.temp.name) / 'occupied'
        path.write_text('unrelated')
        with self.assertRaises(OSError): RelayServer(str(path), self.peer, self.authority)
        self.assertEqual(path.read_text(), 'unrelated')
