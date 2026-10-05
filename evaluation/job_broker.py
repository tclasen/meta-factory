"""Private normalized job observations; database/schema/storage access stays parent-side.

Readers must independently map durable attempts/leases, completion audit events
and physical published objects. Public API status alone is not lease evidence.
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


def project(value, export_id):
    fields = {'export_id', 'status', 'processing_attempts', 'active_lease',
              'lease_fingerprint', 'published_artifacts', 'completion_events'}
    if not isinstance(value, dict) or not fields <= value.keys() or value['export_id'] != export_id:
        raise ValueError('Incomplete or mismatched job observation')
    if value['status'] not in ('pending', 'rejected', 'queued', 'running', 'ready', 'failed'):
        raise ValueError('Invalid normalized job status')
    for key in ('processing_attempts', 'published_artifacts', 'completion_events'):
        if type(value[key]) is not int or not 0 <= value[key] <= 2**31 - 1:
            raise ValueError('Invalid bounded job count')
    fingerprint = value['lease_fingerprint']
    if (type(value['active_lease']) is not bool
            or fingerprint is not None and (not isinstance(fingerprint, str) or not re.fullmatch(r'[0-9a-f]{64}', fingerprint))
            or value['active_lease'] and fingerprint is None):
        raise ValueError('Invalid normalized lease observation')
    # Counts above application limits remain observations, not infrastructure
    # errors: protected oracles must be able to detect retries/duplicate publication.
    return {key: value[key] for key in sorted(fields)}


class JobBroker(AuditBroker):
    """Bounded local capability. reader(export_id) must enforce peer/guard lifetime.

    The inherited endpoint owns authentication, permissions and cleanup mechanics.
    Requests/exception text are never logged; only the fixed projection is sent.
    """
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
                        if (set(request) != {'token', 'export_id'} or not isinstance(request['token'], str)
                                or not hmac.compare_digest(request['token'], self.token)):
                            send(stream, {'status': 'refused'}); continue
                        try:
                            export_id = export_identity(request['export_id'])
                            if self.closing.is_set() or self.remaining <= 0:
                                raise ValueError('Job capability unavailable')
                            self.remaining -= 1
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


def read_job(configuration, export_id, *, timeout=45):
    export_identity(export_id)
    if not 0 < timeout <= 60:raise ValueError('Invalid job request timeout')
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); connection.settimeout(timeout)
    try:
        connection.connect(configuration['socket'])
        with connection.makefile('rwb') as stream:
            send(stream, {'token': configuration['token'], 'export_id': export_id})
            response = receive(stream)
            if set(response) != {'status', 'observation'} or response['status'] != 'observed':
                raise JobObservationError('Job observation unavailable')
            return project(response['observation'], export_id)
    except (OSError, ValueError, KeyError):
        raise JobObservationError('Job observation unavailable') from None
    finally:connection.close()
