"""Private read-only audit observations; SQL and connections stay in the parent."""
import hmac
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import threading
import tempfile
import uuid

from .database_probe import AUDIT_FIELDS

LIMIT = 65536


class AuditObservationError(RuntimeError):
    pass


def request_values(correlations, forbidden_values):
    if (not isinstance(correlations, list) or not 1 <= len(correlations) <= 32
            or any(not isinstance(v, str) for v in correlations)):
        raise ValueError('Invalid audit correlations')
    if any(str(uuid.UUID(v)) != v for v in correlations) or len(set(correlations)) != len(correlations):
        raise ValueError('Invalid audit correlations')
    if (not isinstance(forbidden_values, list) or len(forbidden_values) > 32
            or any(not isinstance(v, str) or not v or '\x00' in v or len(v.encode()) > 4096 for v in forbidden_values)
            or sum(len(v.encode()) for v in forbidden_values) > 16384):
        raise ValueError('Invalid audit text controls')


def project(value):
    """No extra callback fields or arbitrary row payloads cross the capability."""
    if (not isinstance(value, dict) or type(value.get('truncated')) is not bool
            or not isinstance(value.get('events'), list) or len(value['events']) > 128):
        raise ValueError('Invalid audit observation')
    events = []
    for event in value['events']:
        if not isinstance(event, dict):
            raise ValueError('Invalid audit event')
        if event in ({'forbidden_text_present': True}, {'metadata_oversized': True}):
            # Equality alone would accept 1 in place of a true observation.
            key = next(iter(event))
            if event[key] is not True:
                raise ValueError('Invalid audit observation flag')
        elif (set(event) != set(AUDIT_FIELDS)
              or any(v is not None and (not isinstance(v, str) or len(v.encode()) > 256) for v in event.values())):
            raise ValueError('Invalid audit event projection')
        events.append(dict(event))
    return {'truncated': value['truncated'], 'events': events}


def send(stream, value):
    data = json.dumps(value, allow_nan=False).encode() + b'\n'
    if len(data) > LIMIT:
        raise ValueError('Audit message exceeds bound')
    stream.write(data); stream.flush()


def receive(stream):
    data = stream.readline(LIMIT + 1)
    if not data or len(data) > LIMIT or not data.endswith(b'\n'):
        raise ValueError('Incomplete or oversized audit message')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:raise ValueError('Duplicate audit message key')
            result[key] = value
        return result
    value = json.loads(data, object_pairs_hook=pairs)
    if not isinstance(value, dict):raise ValueError('Invalid audit message')
    return value


class AuditBroker:
    """Serve bounded metadata reads through an operator-owned guarded reader.

    reader(correlations, forbidden_values) must bound its commands and check the
    live peer/database binding and guard. It may not execute worker-supplied SQL.
    Neither requests nor exception text are logged; text controls can be secrets.
    """
    def __init__(self, reader, *, request_seconds=10, cleanup_seconds=45, max_requests=128):
        if (not callable(reader) or not 0 < request_seconds <= 30
                or not 0 < cleanup_seconds <= 60 or type(max_requests) is not int or not 1 <= max_requests <= 1024):
            raise ValueError('Invalid audit broker bounds')
        self.reader = reader; self.request_seconds = request_seconds
        self.cleanup_seconds = cleanup_seconds; self.remaining = max_requests
        self.token = secrets.token_hex(32)
        self.directory = Path(tempfile.mkdtemp(prefix='factory-audit-', dir='/tmp'))
        self.path = self.directory / 'observe.sock'
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(str(self.path)); os.chmod(self.path, 0o600)
        self.socket.listen(1); self.socket.settimeout(.1)
        self.closing = threading.Event(); self.idle = threading.Event(); self.idle.set()
        self.connection = None
        self.thread = threading.Thread(target=self._serve, daemon=True); self.thread.start()

    @property
    def configuration(self):
        return {'socket': str(self.path), 'token': self.token}

    def _serve(self):
        while not self.closing.is_set():
            try:connection, _ = self.socket.accept()
            except socket.timeout:continue
            except OSError:break
            self.connection = connection; self.idle.clear()
            try:
                with connection:
                    connection.settimeout(self.request_seconds)
                    with connection.makefile('rwb') as stream:
                        request = receive(stream)
                        if (set(request) != {'token','correlations','forbidden_values'}
                                or not isinstance(request['token'], str)
                                or not hmac.compare_digest(request['token'], self.token)):
                            send(stream, {'status':'refused'}); continue
                        try:
                            request_values(request['correlations'], request['forbidden_values'])
                            if self.closing.is_set() or self.remaining <= 0:
                                raise ValueError('Audit capability unavailable')
                            self.remaining -= 1
                            observed = project(self.reader(request['correlations'], request['forbidden_values']))
                            if self.closing.is_set():raise ValueError('Audit capability revoked')
                            send(stream, {'status':'observed', 'observation':observed})
                        except Exception:
                            send(stream, {'status':'inconclusive'})
            except Exception:
                # Do not retain a malformed request or exception carrying canaries.
                pass
            finally:
                self.connection = None; self.idle.set()

    def wait_idle(self, timeout=None):
        return self.idle.wait(self.cleanup_seconds if timeout is None else timeout)

    def close(self):
        self.closing.set(); self.socket.close()
        connection = self.connection
        if connection is not None:
            try:connection.shutdown(socket.SHUT_RDWR)
            except OSError:pass
        self.thread.join(self.cleanup_seconds)
        if self.thread.is_alive():raise AuditObservationError('Audit reader cleanup incomplete')
        if self.directory.exists():shutil.rmtree(self.directory)

    def __enter__(self):return self
    def __exit__(self, *args):self.close()


def read_audit(configuration, correlations, forbidden_values=(), *, timeout=45):
    """Request metadata only; the capability exposes no query or connection API."""
    correlations, forbidden_values = list(correlations), list(forbidden_values)
    request_values(correlations, forbidden_values)
    if not 0 < timeout <= 60:raise ValueError('Invalid audit request timeout')
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); connection.settimeout(timeout)
    try:
        connection.connect(configuration['socket'])
        with connection.makefile('rwb') as stream:
            send(stream, dict(token=configuration['token'], correlations=correlations, forbidden_values=forbidden_values))
            response = receive(stream)
            if response.get('status') != 'observed':raise AuditObservationError('Audit observation unavailable')
            return project(response['observation'])
    except (OSError, ValueError, KeyError):
        raise AuditObservationError('Audit observation unavailable') from None
    finally:connection.close()
