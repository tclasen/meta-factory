"""Private ordered worker-to-storage staging; commands remain parent-owned."""
from contextlib import contextmanager
import hmac
import math
import socket

from .fault_broker import FaultBroker, control_stream, receive, send
from .faults import FaultRestoreError, FaultSetupError
from .job_broker import export_identity, project_lease, LEASE_FIELDS

WORKER_RECEIPT = {'worker_suspended_verified', 'api_available_verified'}
STORAGE_RECEIPT = {'storage_suspended_verified', 'storage_outage_verified', 'worker_restored_verified'}
RESTART_RECEIPT = {'storage_hold_verified', 'worker_restarted_verified'}


def verified(value, fields):
    if not isinstance(value, dict) or any(value.get(field) is not True for field in fields):
        raise FaultSetupError('Staging transition was not independently verified')
    return {field: True for field in sorted(fields)}


def restart_window(value):
    if not isinstance(value, dict) or set(value) != {'earliest', 'latest'}:
        raise ValueError('Invalid parent restart window')
    try:
        if (any(type(value[key]) not in (int, float) or not math.isfinite(value[key])
                or value[key] < 0 for key in value) or value['latest'] < value['earliest']):
            raise ValueError('Invalid parent restart window')
        return {key: float(value[key]) for key in ('earliest', 'latest')}
    except OverflowError:
        raise ValueError('Invalid parent restart window') from None


def verified_restart(value, export_id=None):
    observation = verified(value, RESTART_RECEIPT)
    observation['restart_window'] = restart_window(value.get('restart_window'))
    if export_id is not None:observation['paused_job'] = project_lease(value.get('paused_job'), export_id)
    return observation


def running_duration(value):
    if not isinstance(value, dict) or not {'minimum', 'maximum'} <= value.keys():
        raise ValueError('Running duration unavailable')
    projected = {key:value[key] for key in ('minimum', 'maximum')}
    try:
        if (any(type(number) not in (int, float) or not math.isfinite(number) or number < 0
                for number in projected.values()) or projected['minimum'] > projected['maximum']):
            raise ValueError('Invalid running duration')
    except OverflowError:raise ValueError('Invalid running duration') from None
    return projected


class StagingBroker(FaultBroker):
    """factory() owns the entire staged lifetime, including partial-failure cleanup.

    It yields a parent handle with observations, verify(), handoff() and restart_worker().
    Handoff must suspend and verify storage before restoring the held worker.
    Restart must independently reverify the storage hold before/after restarting.
    Receipt assertions alone are not implementations of these operations.
    """
    def __init__(self, factory, *, idle_seconds=60, cleanup_seconds=600):
        if not callable(factory): raise ValueError('Trusted staging factory required')
        # Reuse only authenticated endpoint ownership and bounded cleanup machinery.
        super().__init__(['worker', 'storage'], factory, idle_seconds=idle_seconds,
                         cleanup_seconds=cleanup_seconds)

    def _serve(self):
        while not self.closing.is_set():
            try: connection, _ = self.socket.accept()
            except socket.timeout: continue
            except OSError: break
            self.connection = connection; self.idle.clear()
            try:
                with connection:
                    connection.settimeout(self.idle_seconds)
                    with connection.makefile('rwb') as stream:
                        request = receive(stream)
                        if (set(request) != {'token', 'operation'}
                                or not isinstance(request['token'], str)
                                or not hmac.compare_digest(request['token'], self.token)
                                or request['operation'] != 'stage'):
                            send(stream, {'status': 'refused'}); continue
                        if self.aborted or self.closing.is_set():
                            send(stream, {'status': 'abort'}); continue
                        try:
                            with self.factory() as handle:
                                send(stream, {'status': 'worker_held',
                                    'observations': verified(handle.observations, WORKER_RECEIPT)})
                                handed_off = False; restarted = False; timed = False
                                while True:
                                    request = receive(stream)
                                    if request == {'operation': 'restore'}: break
                                    paused = set(request) == {'operation', 'export_id'} and request.get('operation') == 'restart_worker'
                                    if not (set(request) == {'operation'} or paused) or self.closing.is_set() or self.aborted:
                                        raise FaultSetupError('Invalid staging action')
                                    if request['operation'] == 'verify':
                                        fields = STORAGE_RECEIPT if handed_off else WORKER_RECEIPT
                                        status = 'storage_held' if handed_off else 'worker_held'
                                        send(stream, {'status': status, 'observations': verified(handle.verify(), fields)})
                                    elif request['operation'] == 'handoff' and not handed_off:
                                        handed_off = True
                                        observation = verified(handle.handoff(), STORAGE_RECEIPT)
                                        send(stream, {'status': 'storage_held', 'observations': observation})
                                    elif request['operation'] == 'observe_running' and handed_off and not restarted:
                                        timed = True
                                        send(stream, {'status':'running_observed',
                                            'observations':running_duration(handle.observe_running())})
                                    elif request['operation'] == 'restart_worker' and handed_off and not restarted and not timed:
                                        restarted = True
                                        export_id = export_identity(request['export_id']) if paused else None
                                        value = handle.restart_worker(export_id) if paused else handle.restart_worker()
                                        observation = verified_restart(value, export_id)
                                        send(stream, {'status': 'worker_restarted', 'observations': observation})
                                    else:
                                        raise FaultSetupError('Invalid staging order or repeated action')
                            send(stream, {'status': 'restored'})
                        except FaultRestoreError:
                            self.aborted = True; send(stream, {'status': 'abort'})
                        except (EOFError, OSError):
                            self.aborted = True; self.errors.append('client_disconnected')
                        except Exception:
                            self.aborted = True; send(stream, {'status': 'inconclusive'})
            except Exception as error:
                self.errors.append(type(error).__name__)
            finally:
                self.connection = None; self.idle.set()


def receipt(response, status, fields, export_id=None):
    observations = response.get('observations')
    expected = fields | {'restart_window'} if status == 'worker_restarted' else fields
    if export_id is not None:expected = expected | {'paused_job'}
    if (set(response) != {'status', 'observations'} or response['status'] != status
            or not isinstance(observations, dict) or set(observations) != expected
            or any(observations[field] is not True for field in fields)):
        raise FaultRestoreError('Staging receipt unavailable; abort grading')
    if export_id is not None and (not isinstance(observations.get('paused_job'), dict)
            or set(observations['paused_job']) != LEASE_FIELDS):
        raise FaultRestoreError('Paused job receipt unavailable; abort grading')
    if status == 'worker_restarted':
        try:
            return verified_restart(observations, export_id)
        except ValueError as error:
            raise FaultRestoreError('Parent restart window unavailable; abort grading') from error
    return observations


class StagingSession:
    def __init__(self, stream, observations):
        self.stream, self.observations = stream, observations
        self.handed_off = False; self.restarted = False; self.timed = False

    def _action(self, operation, status, fields, export_id=None):
        try:
            request = {'operation': operation}
            if export_id is not None:request['export_id'] = export_id
            send(self.stream, request)
            response = receive(self.stream)
        except (OSError, EOFError, ValueError) as error:
            raise FaultRestoreError('Staging control connection lost') from error
        self.observations = receipt(response, status, fields, export_id)
        return self.observations

    def verify(self):
        return self._action('verify', 'storage_held' if self.handed_off else 'worker_held',
                            STORAGE_RECEIPT if self.handed_off else WORKER_RECEIPT)

    def handoff(self):
        if self.handed_off: raise FaultSetupError('Staging handoff already requested')
        self.handed_off = True
        return self._action('handoff', 'storage_held', STORAGE_RECEIPT)

    def observe_running(self):
        if not self.handed_off or self.restarted:
            raise FaultSetupError('Running observation requires handoff without a restart')
        self.timed = True
        try:
            send(self.stream, {'operation':'observe_running'}); response = receive(self.stream)
            if (set(response) != {'status', 'observations'} or response['status'] != 'running_observed'
                    or not isinstance(response['observations'], dict)
                    or set(response['observations']) != {'minimum', 'maximum'}):
                raise ValueError('Invalid running receipt')
            return running_duration(response['observations'])
        except (OSError, EOFError, ValueError) as error:
            raise FaultRestoreError('Running duration receipt unavailable') from error

    def restart_worker(self, export_id=None):
        if not self.handed_off or self.restarted or self.timed:
            raise FaultSetupError('Worker restart requires a single completed staging handoff')
        if export_id is not None:export_identity(export_id)
        self.restarted = True
        return self._action('restart_worker', 'worker_restarted', RESTART_RECEIPT, export_id)


@contextmanager
def remote_staging(configuration, *, timeout=360):
    """Worker held initially; grader enqueues/approves before requesting handoff."""
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); connection.settimeout(timeout)
    try:
        try: connection.connect(configuration['socket'])
        except OSError as error: raise FaultSetupError('Staging endpoint unavailable') from error
        with control_stream(connection) as stream:
            try:
                send(stream, {'token': configuration['token'], 'operation': 'stage'})
                response = receive(stream)
            except (OSError, EOFError, ValueError) as error:
                raise FaultSetupError('Staging setup unavailable') from error
            if response.get('status') == 'abort': raise FaultRestoreError('Staging broker aborted')
            if response.get('status') != 'worker_held': raise FaultSetupError('Worker hold unavailable')
            # Even an invalid receipt may describe an active parent context; always
            # request restoration after the parent has acknowledged a worker hold.
            try:
                observations = receipt(response, 'worker_held', WORKER_RECEIPT)
                yield StagingSession(stream, observations)
            finally:
                try:
                    send(stream, {'operation': 'restore'}); response = receive(stream)
                except (OSError, EOFError, ValueError) as error:
                    raise FaultRestoreError('Staging restoration connection lost') from error
                if response != {'status': 'restored'}:
                    raise FaultRestoreError('Staging restoration was not verified')
    finally:
        connection.close()
