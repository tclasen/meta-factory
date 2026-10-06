"""Private normalized job observations; database/schema/storage access stays parent-side.

Readers must independently map durable attempts/leases, completion audit events
and physical published objects. The fingerprint represents retained owner/token
material even after expiry; None means no complete owner/token pair. Public API
status alone is not lease evidence.
This module supplies a boundary, not the database/object-store reader or scheduler.
"""
import hmac
import re
import socket
import uuid
from .audit_broker import AuditBroker, AuditObservationError
from .fault_broker import send, receive


class JobObservationError(RuntimeError):
    pass


def export_identity(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError('Canonical export identity required')
    return value


LEASE_FIELDS = {'export_id', 'status', 'processing_attempts', 'active_lease',
                'lease_fingerprint', 'completion_events'}
ARTIFACT_HISTORY_FIELDS = {'versions', 'delete_markers', 'keys', 'current_objects',
                           'current_delete_markers', 'history_complete'}


def project_artifact_history(value):
    """Private physical counts only; no raw keys, IDs or completeness assertion."""
    if (not isinstance(value, dict) or set(value) != ARTIFACT_HISTORY_FIELDS
            or value['history_complete'] is not False
            or any(type(value[key]) is not int or not 0 <= value[key] <= 2**31-1
                   for key in ARTIFACT_HISTORY_FIELDS-{'history_complete'})
            or value['current_objects']+value['current_delete_markers'] != value['keys']
            or value['versions'] < value['current_objects']
            or value['delete_markers'] < value['current_delete_markers']
            or (value['keys'] == 0) != (value['versions']+value['delete_markers'] == 0)
            or value['keys'] > value['versions']+value['delete_markers']):
        raise ValueError('Invalid independent artifact history')
    return {key: value[key] for key in sorted(ARTIFACT_HISTORY_FIELDS)}


def project_lease(value, export_id):
    if not isinstance(value, dict) or not LEASE_FIELDS <= value.keys() or value['export_id'] != export_id:
        raise ValueError('Incomplete or mismatched durable job observation')
    if value['status'] not in ('pending', 'rejected', 'queued', 'running', 'ready', 'failed'):
        raise ValueError('Invalid normalized job status')
    for key in ('processing_attempts', 'completion_events'):
        if type(value[key]) is not int or not 0 <= value[key] <= 2**31 - 1:
            raise ValueError('Invalid bounded job count')
    fingerprint = value['lease_fingerprint']
    if (type(value['active_lease']) is not bool
            or fingerprint is not None and (not isinstance(fingerprint, str) or not re.fullmatch(r'[0-9a-f]{64}', fingerprint))
            or value['active_lease'] and fingerprint is None):
        raise ValueError('Invalid normalized lease observation')
    return {key: value[key] for key in sorted(LEASE_FIELDS)}


def project(value, export_id):
    observation = project_lease(value, export_id)
    count = value.get('published_artifacts')
    if type(count) is not int or not 0 <= count <= 2**31 - 1:
        raise ValueError('Invalid independent physical artifact count')
    observation['published_artifacts'] = count
    if 'artifact_history' in value:
        history = project_artifact_history(value['artifact_history'])
        if history['current_objects'] != count:
            raise ValueError('Independent artifact observations disagree')
        observation['artifact_history'] = history
    # Above-limit counts remain visible to the oracle rather than being hidden
    # as infrastructure errors. Durable-only reads never fabricate this field.
    return {key: observation[key] for key in sorted(observation)}


class JobBroker(AuditBroker):
    """Bounded local capability. reader(export_id) must enforce peer/guard lifetime.

    The inherited endpoint owns authentication, permissions and cleanup mechanics.
    Requests/exception text are never logged; only the fixed projection is sent.
    """
    def __init__(self, reader, *, durable_reader=None, **bounds):
        if durable_reader is not None and not callable(durable_reader):
            raise ValueError('Trusted durable job reader required')
        self.durable_reader = durable_reader
        super().__init__(reader, **bounds)

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
                        durable = set(request) == {'token', 'export_id', 'operation'} and request.get('operation') == 'read_lease'
                        if (not (set(request) == {'token', 'export_id'} or durable) or not isinstance(request['token'], str)
                                or not hmac.compare_digest(request['token'], self.token)):
                            send(stream, {'status': 'refused'}); continue
                        try:
                            export_id = export_identity(request['export_id'])
                            if self.closing.is_set() or self.remaining <= 0:
                                raise ValueError('Job capability unavailable')
                            self.remaining -= 1
                            if durable:
                                if self.durable_reader is None:raise ValueError('Durable capability unavailable')
                                observation = project_lease(self.durable_reader(export_id), export_id)
                            else:
                                observation = project(self.reader(export_id), export_id)
                            if self.closing.is_set():raise ValueError('Job capability revoked')
                            send(stream, {'status': 'observed', 'observation': observation})
                        except Exception:
                            send(stream, {'status': 'inconclusive'})
            except Exception:
                pass
            finally:
                self.connection = None; self.idle.set()

    def close(self):
        try:super().close()
        except AuditObservationError:
            raise JobObservationError('Job reader cleanup incomplete') from None


def _read(configuration, export_id, *, timeout, durable):
    export_identity(export_id)
    if not 0 < timeout <= 60:raise ValueError('Invalid job request timeout')
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); connection.settimeout(timeout)
    try:
        connection.connect(configuration['socket'])
        with connection.makefile('rwb') as stream:
            request = {'token': configuration['token'], 'export_id': export_id}
            if durable:request['operation'] = 'read_lease'
            send(stream, request)
            response = receive(stream)
            if set(response) != {'status', 'observation'} or response['status'] != 'observed':
                raise JobObservationError('Job observation unavailable')
            return (project_lease if durable else project)(response['observation'], export_id)
    except (OSError, ValueError, KeyError):
        raise JobObservationError('Job observation unavailable') from None
    finally:connection.close()


def read_job(configuration, export_id, *, timeout=45):
    return _read(configuration, export_id, timeout=timeout, durable=False)


def read_lease(configuration, export_id, *, timeout=45):
    """Durable lease/attempt/event data only; no physical artifact count is returned."""
    return _read(configuration, export_id, timeout=timeout, durable=True)
