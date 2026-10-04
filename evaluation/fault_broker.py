"""Parent-owned, local fault control; workers never receive sandbox commands."""

from contextlib import contextmanager
import hmac
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import tempfile
import threading

from .faults import FaultRestoreError, FaultSetupError
from .workload_probe import NAME


LIMIT = 4096


def send(stream, value):
    stream.write(json.dumps(value).encode() + b'\n')
    stream.flush()


def receive(stream):
    line = stream.readline(LIMIT + 1)
    if not line:
        raise EOFError('Fault connection closed')
    if len(line) > LIMIT or not line.endswith(b'\n'):
        raise ValueError('Oversized fault request')
    value = json.loads(line)
    if not isinstance(value, dict):
        raise ValueError('Invalid fault request')
    return value


class FaultBroker:
    """Serve one bounded fault context at a time using parent-owned callbacks.

    The factory maps a reviewed role to an already-guarded sandbox operation.
    It must bound all operations and prevent commands after guard expiry.
    No command strings, workload names or shell arguments cross this protocol.
    """
    def __init__(self, roles, factory, *, idle_seconds=60, cleanup_seconds=600):
        if not roles or any(not isinstance(role, str) or not NAME.fullmatch(role) for role in roles):
            raise ValueError('Invalid fault roles')
        if not 0 < idle_seconds <= 600 or not 0 < cleanup_seconds <= 600:
            raise ValueError('Invalid broker bounds')
        self.roles = frozenset(roles)
        self.factory = factory
        self.idle_seconds = idle_seconds
        self.cleanup_seconds = cleanup_seconds
        self.token = secrets.token_hex(32)
        self.directory = Path(tempfile.mkdtemp(prefix='factory-fault-', dir='/tmp'))
        self.path = self.directory / 'control.sock'
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(str(self.path)); os.chmod(self.path, 0o600)
        self.socket.listen(1); self.socket.settimeout(0.1)
        self.closing = threading.Event()
        self.idle = threading.Event(); self.idle.set()
        self.aborted = False
        self.errors = []
        self.connection = None
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    @property
    def configuration(self):
        # Keep this capability in the private grader target, outside app mounts.
        return {'socket': str(self.path), 'token': self.token}

    def _serve(self):
        while not self.closing.is_set():
            try:
                connection, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.connection = connection
            self.idle.clear()
            try:
                with connection:
                    connection.settimeout(self.idle_seconds)
                    with connection.makefile('rwb') as stream:
                        request = receive(stream)
                        if (set(request) != {'token', 'operation', 'role'}
                                or not isinstance(request['token'], str)
                                or not hmac.compare_digest(request['token'], self.token)
                                or request['operation'] != 'suspend' or request['role'] not in self.roles):
                            send(stream, {'status': 'refused'})
                            continue
                        if self.aborted or self.closing.is_set():
                            send(stream, {'status': 'abort'})
                            continue
                        try:
                            with self.factory(request['role']) as observations:
                                # Project only explicit parent observations. Never
                                # forward arbitrary callback data or diagnostics.
                                verified = (isinstance(observations, dict)
                                            and observations.get('service_outage_verified') is True)
                                send(stream, {'status': 'suspended',
                                              'observations': {'service_outage_verified': verified}})
                                ending = receive(stream)
                                if ending != {'operation': 'restore'}:
                                    raise FaultSetupError('Invalid fault completion')
                            send(stream, {'status': 'restored'})
                        except FaultRestoreError:
                            self.aborted = True
                            send(stream, {'status': 'abort'})
                        except (EOFError, OSError):
                            # The context manager has already attempted restoration.
                            self.aborted = True
                            self.errors.append('client_disconnected')
                        except Exception:
                            self.aborted = True
                            send(stream, {'status': 'inconclusive'})
            except Exception as error:
                self.errors.append(type(error).__name__)
            finally:
                self.connection = None
                self.idle.set()

    def wait_idle(self, timeout=None):
        return self.idle.wait(self.cleanup_seconds if timeout is None else timeout)

    def close(self):
        self.closing.set()
        self.socket.close()
        connection = self.connection
        if connection is not None:
            try: connection.shutdown(socket.SHUT_RDWR)
            except OSError: pass
        self.thread.join(self.cleanup_seconds)
        if self.thread.is_alive():
            self.aborted = True
            raise FaultRestoreError('Fault broker cleanup did not finish')
        shutil.rmtree(self.directory)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


@contextmanager
def remote_fault(configuration, role, *, timeout=300):
    """Request one reviewed fault; only the parent controller can execute it."""
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    try:
        try:
            connection.connect(configuration['socket'])
        except OSError as error:
            raise FaultSetupError('Fault-control connection unavailable') from error
        with connection.makefile('rwb') as stream:
            try:
                send(stream, {'token': configuration['token'], 'operation': 'suspend', 'role': role})
                response = receive(stream)
            except (OSError, EOFError, ValueError) as error:
                raise FaultSetupError('Fault-control setup unavailable') from error
            if response.get('status') == 'abort':
                raise FaultRestoreError('Parent fault restoration failed')
            if response.get('status') != 'suspended':
                raise FaultSetupError('Parent fault precondition unavailable')
            try:
                yield response.get('observations', {})
            finally:
                try:
                    send(stream, {'operation': 'restore'})
                    response = receive(stream)
                except (OSError, EOFError, ValueError) as error:
                    raise FaultRestoreError('Lost fault-control connection; abort grading') from error
                if response.get('status') != 'restored':
                    raise FaultRestoreError('Parent did not verify restoration')
    finally:
        connection.close()
