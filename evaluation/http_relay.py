"""Fixed-destination HTTP transport for a network-isolated evaluator browser.

No request URLs, headers, bodies or exception text are logged. The operator owns
both endpoints; application input can never choose a connection destination.
Unsupported framing/upgrades and exceeded bounds are transport uncertainty, not
application acceptance failures. The outer container guard remains mandatory.
"""
import collections
import http.client
import http.server
import ipaddress
import os
from pathlib import Path
import re
import socket
import socketserver
import threading
import time

HOP = {'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
       'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade'}
METHODS = {'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'}
COUNTERS = {'completed', 'refused', 'upstream_error', 'request_limit',
            'response_limit', 'deadline', 'client_disconnect', 'handler_error'}


class RelayError(Exception):
    def __init__(self, kind, status=502):
        self.kind, self.status = kind, status


class ClientDisconnected(Exception):
    pass


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__('localhost', timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        try:
            self.sock.connect(self.path)
        except BaseException:
            self.sock.close()
            raise


class RelayServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address, upstream, authority, *, request_seconds=30,
                 max_request_bytes=8 * 1024 * 1024, max_response_bytes=128 * 1024 * 1024,
                 check=lambda: None):
        if (not isinstance(authority, str) or not re.fullmatch(r'127\.0\.0\.1:[0-9]{1,5}', authority)
                or not 1 <= int(authority.rsplit(':', 1)[1]) <= 65535):
            raise ValueError('Expected fixed loopback browser authority')
        if (not isinstance(upstream, dict) or upstream.get('kind') not in ('tcp', 'unix')
                or not callable(check) or type(request_seconds) not in (int, float)
                or not 0 < request_seconds <= 60):
            raise ValueError('Invalid relay configuration')
        for bound in (max_request_bytes, max_response_bytes):
            if type(bound) is not int or not 1 <= bound <= 256 * 1024 * 1024:
                raise ValueError('Invalid relay byte bound')
        if upstream['kind'] == 'tcp':
            if set(upstream) != {'kind', 'host', 'port'}:
                raise ValueError('Incomplete fixed TCP peer')
            if not isinstance(upstream['host'], str):
                raise ValueError('Invalid fixed peer address')
            ipaddress.ip_address(upstream['host'])  # No per-request DNS or URL resolution.
            if type(upstream['port']) is not int or not 1 <= upstream['port'] <= 65535:
                raise ValueError('Invalid fixed peer port')
        else:
            if (set(upstream) != {'kind', 'path'} or not isinstance(upstream['path'], str)
                    or not upstream['path'].startswith('/') or '\x00' in upstream['path']
                    or len(os.fsencode(upstream['path'])) > 100):
                raise ValueError('Invalid private socket path')
        self.unix_path = None
        if isinstance(address, str):
            if not address.startswith('/') or '\x00' in address or len(os.fsencode(address)) > 100:
                raise ValueError('Invalid relay listener path')
            self.address_family = socket.AF_UNIX
            self.unix_path = Path(address)
        elif not (isinstance(address, tuple) and len(address) == 2 and address[0] == '127.0.0.1'
                  and type(address[1]) is int and 0 <= address[1] <= 65535):
            raise ValueError('TCP relay must listen on loopback')
        self.upstream, self.authority, self.check = dict(upstream), authority, check
        self.request_seconds = request_seconds
        self.max_request_bytes, self.max_response_bytes = max_request_bytes, max_response_bytes
        self.counts = collections.Counter()
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(4)
        self.closed = threading.Event()
        self.handlers = set()
        self.socket_identity = None
        super().__init__(address, RelayHandler)
        if self.unix_path is not None:
            os.chmod(self.unix_path, 0o600)
            self.socket_identity = self.unix_path.stat().st_ino

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name = 'factory-http-relay'
        self.server_port = self.server_address[1] if isinstance(self.server_address, tuple) else 0

    def record(self, kind):
        if kind not in COUNTERS:
            raise ValueError('Invalid relay observation')
        with self.lock:
            self.counts[kind] += 1

    def observation(self):
        with self.lock:
            return dict(self.counts)

    def handle_error(self, request, client_address):
        self.record('handler_error')

    def connection(self):
        self.check()
        if self.closed.is_set():
            raise RelayError('upstream_error')
        peer = self.upstream
        if peer['kind'] == 'unix':
            return UnixConnection(peer['path'], self.request_seconds)
        return http.client.HTTPConnection(peer['host'], peer['port'], timeout=self.request_seconds)

    def server_close(self):
        self.closed.set()
        super().server_close()
        with self.lock:
            active = list(self.handlers)
        for handler in active:
            handler.abort()
        deadline = time.monotonic() + self.request_seconds + 1
        settled = all(handler.done.wait(max(0, deadline - time.monotonic())) for handler in active)
        if (self.unix_path is not None and self.socket_identity is not None
                and self.unix_path.exists() and self.unix_path.stat().st_ino == self.socket_identity):
            self.unix_path.unlink()
        if not settled:
            raise RuntimeError('Relay cleanup incomplete')


class RelayHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'FactoryRelay'
    sys_version = ''

    def log_message(self, *args):
        pass

    def abort(self):
        self.dead.set()
        with self.socket_lock:
            for stream in self.sockets:
                try:
                    stream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def handle(self):
        self.started = time.monotonic()
        self.dead = threading.Event()
        self.sockets = [self.connection]
        self.socket_lock = threading.Lock()
        self.done = threading.Event()
        with self.server.lock:
            self.server.handlers.add(self)
        self.connection.settimeout(self.server.request_seconds)
        expired = threading.Event()
        def expire():
            expired.set()
            self.server.record('deadline')
            self.abort()
        timer = threading.Timer(self.server.request_seconds, expire)
        timer.daemon = True
        timer.start()
        try:
            # One request per connection bounds lifetime and removes ambiguity
            # about unread client bytes becoming a second upstream request.
            self.close_connection = True
            if self.server.closed.is_set():
                self.abort()
            else:
                self.handle_one_request()
        finally:
            timer.cancel()
            timer.join()
            # BaseHTTPRequestHandler swallows socket timeouts while parsing.
            # The socket can expire before the timer thread gets scheduled;
            # retain deadline evidence even when that callback was cancelled.
            if not expired.is_set() and time.monotonic() - self.started >= self.server.request_seconds:
                self.server.record('deadline')
            with self.server.lock:
                self.server.handlers.discard(self)
            self.done.set()

    def send_error(self, code, message=None, explain=None):
        # BaseHTTP parser diagnostics can contain attacker-controlled text.
        self.server.record('refused')
        self.safe_error(code)

    def handle_expect_100(self):
        self.close_connection = True
        self.server.record('refused')
        self.safe_error(417)
        return False

    def safe_error(self, status):
        try:
            body = b'{"error":"relay_unavailable"}'
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            if getattr(self, 'command', None) != 'HEAD':
                self.wfile.write(body)
        except OSError:
            pass

    def exact(self, size):
        data = self.rfile.read(size)
        if len(data) != size:
            raise RelayError('refused', 400)
        return data

    def request_body(self):
        lengths, encoding = self.headers.get_all('Content-Length', []), self.headers.get_all('Transfer-Encoding', [])
        if len(lengths) > 1 or len(encoding) > 1 or lengths and encoding:
            raise RelayError('refused', 400)
        if encoding:
            if encoding[0].lower().strip() != 'chunked':
                raise RelayError('refused', 400)
            result = bytearray()
            while True:
                line = self.rfile.readline(4097)
                if not re.fullmatch(rb'[0-9a-fA-F]{1,16}\r\n', line):
                    raise RelayError('refused', 400)
                count = int(line.strip(), 16)
                if count == 0:
                    if self.exact(2) != b'\r\n':
                        raise RelayError('refused', 400)  # Unsupported trailers.
                    return bytes(result)
                if len(result) + count > self.server.max_request_bytes:
                    raise RelayError('request_limit', 413)
                result.extend(self.exact(count))
                if self.exact(2) != b'\r\n':
                    raise RelayError('refused', 400)
        value = lengths[0] if lengths else '0'
        if not re.fullmatch(r'[0-9]{1,12}', value):
            raise RelayError('refused', 400)
        count = int(value)
        if count > self.server.max_request_bytes:
            raise RelayError('request_limit', 413)
        return self.exact(count)

    def forward(self):
        acquired = False
        upstream = None
        sent_headers = False
        self.close_connection = True
        try:
            if (self.command not in METHODS or not self.path.startswith('/') or self.path.startswith('//')
                    or self.requestline.split()[1].startswith('//')
                    or any(ord(c) < 32 or ord(c) == 127 for c in self.path)
                    or self.headers.get_all('Host', []) != [self.server.authority]
                    or sum(len(k) + len(v) for k, v in self.headers.items()) > 65536
                    or self.headers.get('Upgrade') is not None or self.headers.get('Expect') is not None):
                raise RelayError('refused', 400)
            remaining = self.server.request_seconds - (time.monotonic() - self.started)
            acquired = self.server.slots.acquire(timeout=max(0, remaining))
            if not acquired or self.dead.is_set():
                raise RelayError('upstream_error')
            body = self.request_body()
            upstream = self.server.connection()
            remaining = self.server.request_seconds - (time.monotonic() - self.started)
            if remaining <= 0:
                raise RelayError('upstream_error')
            upstream.timeout = remaining
            upstream.connect()
            with self.socket_lock:
                self.sockets.append(upstream.sock)
                if self.dead.is_set():
                    upstream.sock.shutdown(socket.SHUT_RDWR)
                    raise RelayError('upstream_error')
            self.server.check()
            excluded = HOP | {'host', 'content-length'} | {
                value.strip().lower() for field in self.headers.get_all('Connection', []) for value in field.split(',')}
            upstream.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
            upstream.putheader('Host', self.server.authority)
            upstream.putheader('Connection', 'close')
            for key, value in self.headers.items():
                if key.lower() not in excluded:
                    upstream.putheader(key, value)
            upstream.putheader('Content-Length', str(len(body)))
            upstream.endheaders(body)
            response = upstream.getresponse()
            self.server.check()
            headers = response.getheaders()
            lengths = [v for k, v in headers if k.lower() == 'content-length']
            encodings = [v for k, v in headers if k.lower() == 'transfer-encoding']
            if (response.status < 200 or len(lengths) > 1 or len(encodings) > 1 or lengths and encodings
                    or lengths and not re.fullmatch(r'[0-9]{1,12}', lengths[0])
                    or encodings and encodings[0].lower().strip() != 'chunked'
                    or sum(len(k) + len(v) for k, v in headers) > 65536):
                raise RelayError('upstream_error')
            no_body = self.command == 'HEAD' or response.status in (204, 304)
            expected = int(lengths[0]) if lengths else None
            if not no_body and expected is not None and expected > self.server.max_response_bytes:
                raise RelayError('response_limit')
            excluded = HOP | {'content-length'} | {
                v.strip().lower() for k, value in headers if k.lower() == 'connection' for v in value.split(',')}
            self.send_response_only(response.status)
            for key, value in headers:
                if key.lower() not in excluded:
                    self.send_header(key, value)
            self.send_header('Connection', 'close')
            if expected is not None:
                self.send_header('Content-Length', str(expected))
            elif not no_body:
                self.send_header('Transfer-Encoding', 'chunked')
            try:
                self.end_headers()
            except OSError:
                raise ClientDisconnected from None
            sent_headers = True
            received = 0
            if not no_body:
                while True:
                    data = response.read1(65536)
                    if not data:
                        break
                    received += len(data)
                    if received > self.server.max_response_bytes:
                        raise RelayError('response_limit')
                    self.server.check()
                    try:
                        if expected is None:
                            self.wfile.write(('%x\r\n' % len(data)).encode() + data + b'\r\n')
                        else:
                            self.wfile.write(data)
                        self.wfile.flush()
                    except OSError:
                        raise ClientDisconnected from None
                if expected is not None and received != expected:
                    raise RelayError('upstream_error')
                if expected is None:
                    try:
                        self.wfile.write(b'0\r\n\r\n')
                    except OSError:
                        raise ClientDisconnected from None
            self.server.check()
            self.server.record('completed')
        except ClientDisconnected:
            self.server.record('client_disconnect')
        except Exception as error:
            kind = error.kind if isinstance(error, RelayError) else 'upstream_error'
            self.server.record(kind)
            if not sent_headers:
                self.safe_error(error.status if isinstance(error, RelayError) else 502)
        finally:
            if upstream is not None:
                upstream.close()
            if acquired:
                self.server.slots.release()

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_CONNECT = do_TRACE = forward
