"""Operator-only opaque TCP bridge to the owned VM loopback application port."""
import struct
import ipaddress
import json
import os
import selectors
import signal
import math
import sys
import socket
import socketserver
import threading
import time

config = json.loads(sys.argv[1])
if (set(config) != {'nonce','max_seconds','expires_at'}
        or not isinstance(config['nonce'],str) or len(config['nonce'])!=32
        or any(c not in '0123456789abcdef' for c in config['nonce'])
        or any(type(config[k]) not in (int,float) or not math.isfinite(config[k]) or config[k]<=0 for k in ('max_seconds','expires_at'))
        or config['max_seconds']>26*3600):
    raise ValueError('Bounded operator bridge lifetime required')
started = time.monotonic()
wall_started = time.time()
closed = threading.Event()
counts = {'connections': 0, 'completed': 0, 'errors': 0, 'bytes': 0, 'active': 0}
lock = threading.Lock()
slots = threading.BoundedSemaphore(4)


def live():
    return not closed.is_set() and max(time.monotonic()-started, time.time()-wall_started) < config['max_seconds'] and time.time()<config['expires_at']


import fcntl
# Linux read-only SIOCGIFADDR (0x8915), verified against the kernel UAPI.
# Avoid provisioning an iproute2 dependency in the grading VM.
with open('/proc/net/route') as stream:
    raw = stream.read(16385)
if len(raw) > 16384:
    raise ValueError('Bounded default route required')
interfaces = {fields[0] for line in raw.splitlines()[1:]
              if len(fields := line.split()) >= 8 and fields[1] == '00000000'
              and fields[7] == '00000000' and int(fields[3], 16) & 2}
if len(interfaces) != 1:
    raise ValueError('Unique VM default-route interface required')
interface = next(iter(interfaces)).encode('ascii')
if not 1 <= len(interface) < 16:
    raise ValueError('Bounded Linux interface required')
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as descriptor:
    value = fcntl.ioctl(descriptor.fileno(), 0x8915, struct.pack('256s', interface))
    address = ipaddress.ip_address(socket.inet_ntoa(value[20:24]))
if (not address.is_private or address.is_loopback or address.is_link_local
        or address.is_unspecified or address.is_multicast):
    raise ValueError('Private nonloopback VM interface required')


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        if not slots.acquire(blocking=False):
            return
        upstream = None
        with lock:
            counts['connections'] += 1
            counts['active'] += 1
        try:
            upstream = socket.create_connection(('127.0.0.1', 8080), timeout=5)
            self.request.setblocking(False)
            upstream.setblocking(False)
            total = 0
            idle = time.monotonic()
            with selectors.DefaultSelector() as selector:
                selector.register(self.request, selectors.EVENT_READ, upstream)
                selector.register(upstream, selectors.EVENT_READ, self.request)
                while selector.get_map() and live():
                    if time.monotonic()-idle > 30:
                        raise TimeoutError('Opaque relay idle bound')
                    for key, _ in selector.select(.1):
                        data = key.fileobj.recv(65536)
                        if not data:
                            selector.unregister(key.fileobj)
                            key.data.shutdown(socket.SHUT_WR)
                            continue
                        idle = time.monotonic()
                        total += len(data)
                        if total > 64*1024**2:
                            raise ValueError('Opaque relay byte bound')
                        # Bound backpressure without logging or interpreting bytes.
                        key.data.settimeout(5)
                        key.data.sendall(data)
                        key.data.setblocking(False)
            with lock:
                counts['completed'] += 1
                counts['bytes'] += total
        except Exception:
            with lock:
                counts['errors'] += 1
        finally:
            if upstream is not None:
                upstream.close()
            with lock:
                counts['active'] -= 1
            slots.release()


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False


def stop(*unused):
    closed.set()


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
server=Server((str(address), 8080), Handler)
with server:
    server.timeout = .2
    ticks = open('/proc/self/stat').read().rsplit(')', 1)[1].split()[19]
    print(json.dumps(dict(outcome='owned_tcp_relay_ready', pid=os.getpid(),
                         start_ticks=ticks, uid=os.getuid(), nonce=config['nonce'], address=str(address),
                         port=8080, upstream='127.0.0.1:8080')), flush=True)
    while live():
        server.handle_request()
closed.set()
settle=time.monotonic()+6
while counts['active'] and time.monotonic()<settle:
    time.sleep(.02)
print(json.dumps(dict(outcome='owned_tcp_relay_stopped', counts=counts, nonce=config['nonce'])), flush=True)
