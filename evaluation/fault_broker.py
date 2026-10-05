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
    def __init__(self, roles, factory, *, idle_seconds=60, cleanup_seconds=600, restart_actions=None):
        if not roles or any(not isinstance(role, str) or not NAME.fullmatch(role) for role in roles):
            raise ValueError('Invalid fault roles')
        if not 0 < idle_seconds <= 600 or not 0 < cleanup_seconds <= 600:
            raise ValueError('Invalid broker bounds')
        restart_actions = {} if restart_actions is None else restart_actions
        if (not isinstance(restart_actions, dict) or any(
                not isinstance(pair, tuple) or len(pair) != 2 or pair[0] == pair[1]
                or any(role not in roles for role in pair) or not callable(action)
                for pair, action in restart_actions.items())):
            raise ValueError('Restart actions require distinct reviewed fault roles')
        self.restart_actions = dict(restart_actions)
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
                                projected = {'service_outage_verified': verified}
                                if isinstance(observations, dict) and 'workload_suspended_verified' in observations:
                                    projected['workload_suspended_verified'] = observations['workload_suspended_verified'] is True
                                if isinstance(observations, dict) and 'audit_insert_failure_verified' in observations:
                                    projected['audit_insert_failure_verified'] = observations['audit_insert_failure_verified'] is True
                                send(stream, {'status': 'suspended', 'observations': projected})
                                restarted = False
                                while True:
                                    ending = receive(stream)
                                    if ending == {'operation': 'restore'}:
                                        break
                                    if (set(ending) != {'operation', 'role'} or ending['operation'] != 'restart'
                                            or not isinstance(ending['role'], str) or restarted
                                            or self.closing.is_set() or self.aborted):
                                        raise FaultSetupError('Invalid held-fault action')
                                    action = self.restart_actions.get((request['role'], ending['role']))
                                    if action is None:
                                        raise FaultSetupError('Held-fault action unavailable')
                                    restarted = True
                                    receipt = action()
                                    if (not isinstance(receipt, dict)
                                            or receipt.get('workload_restarted_verified') is not True
                                            or receipt.get('held_fault_verified') is not True):
                                        raise FaultSetupError('Held-fault action was not verified')
                                    send(stream, {'status': 'restarted', 'observations': {
                                        'workload_restarted_verified': True, 'held_fault_verified': True}})
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
def control_stream(connection):
    stream = connection.makefile('rwb')
    try:
        yield stream
    finally:
        try:
            stream.close()
        except OSError as error:
            raise FaultRestoreError('Fault-control stream cleanup failed; abort grading') from error


@contextmanager
def remote_fault_session(configuration, role, *, timeout=360):
    """Request one reviewed fault; only the parent controller can execute it."""
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    try:
        try:
            connection.connect(configuration['socket'])
        except OSError as error:
            raise FaultSetupError('Fault-control connection unavailable') from error
        with control_stream(connection) as stream:
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
                yield FaultSession(stream, response.get('observations', {}))
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


class FaultSession:
    """One held fault, optionally one parent-reviewed restart of another role."""
    def __init__(self, stream, observations):
        self.stream = stream
        self.observations = observations
        self.restarted = False

    def restart(self, role):
        if self.restarted or not isinstance(role, str) or not NAME.fullmatch(role):
            raise FaultSetupError('Invalid held-fault restart request')
        self.restarted = True
        try:
            send(self.stream, {'operation': 'restart', 'role': role})
            response = receive(self.stream)
        except (OSError, EOFError, ValueError) as error:
            raise FaultRestoreError('Held-fault control connection lost') from error
        if response != {'status': 'restarted', 'observations': {
                'workload_restarted_verified': True, 'held_fault_verified': True}}:
            raise FaultRestoreError('Held-fault restart not verified; abort grading')
        return response['observations']


@contextmanager
def remote_fault(configuration, role, *, timeout=360):
    """Request one reviewed fault; only the parent controller can execute it."""
    with remote_fault_session(configuration, role, timeout=timeout) as session:
        yield session.observations
